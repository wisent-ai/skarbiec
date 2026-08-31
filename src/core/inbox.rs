// Donation inbox and item provenance (docs/design/bond.md).
//
// p2p v2: a donation no longer merges on arrival — it lands in a per-vault
// inbox file next to the vault (`<vault>.donations.json`, owner-only mode),
// and the owner merges or drops it with donation-accept / donation-reject.
// Provenance: every item carries `written_by` (the uid or consumer that first
// wrote it), and an overwriting donation is accepted only when its `from`
// claim matches. v1 trust model: the donate token's consumer IS the writer
// identity; `from` is an unsigned claim carried for the owner's inspection.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use crate::core::{crypto, vault::Vault, vault_path};

fn now_iso() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn inbox_path() -> PathBuf {
    vault_path().with_extension("donations.json")
}

fn load_inbox() -> Result<Value> {
    let path = inbox_path();
    if !path.exists() {
        return Ok(json!({"donations": []}));
    }
    let body =
        std::fs::read_to_string(&path).with_context(|| format!("read inbox {}", path.display()))?;
    Ok(serde_json::from_str(&body)?)
}

fn save_inbox(doc: &Value) -> Result<()> {
    let path = inbox_path();
    std::fs::write(&path, serde_json::to_string_pretty(doc)?)?;
    Command::new("chmod").arg("600").arg(&path).status().ok();
    Ok(())
}

/// Writer of the active canonical revision.
pub fn written_by(vault: &Vault, id: &str) -> Option<String> {
    vault
        .doc()
        .get("items")
        .and_then(|items| items.get(id))
        .and_then(|item| item.get("current"))
        .and_then(|current| current.get("written_by"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

pub fn managed_by_weles(vault: &Vault, id: &str) -> bool {
    vault
        .doc()
        .get("items")
        .and_then(|items| items.get(id))
        .and_then(|item| item.get("management"))
        .is_some_and(|management| {
            management.get("mode").and_then(Value::as_str) == Some("managed")
                && management.get("controller").and_then(Value::as_str) == Some("weles")
        })
}

/// What an inbound donation for `item_id` may do, given current provenance.
/// `from` is the writer identity claimed by the donor (v1: the consumer).
pub fn admission(vault: &Vault, item_id: &str, from: &str) -> &'static str {
    if crate::credential::lifecycle_owned_item(vault, item_id) {
        return "credential-lifecycle";
    }
    let exists = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .is_some_and(|items| items.contains_key(item_id));
    if !exists {
        return "append";
    }
    if managed_by_weles(vault, item_id) {
        return "managed";
    }
    match written_by(vault, item_id) {
        Some(owner) if owner == from => "overwrite",
        Some(_) => "not-owner",
        // Items written before provenance existed keep the original v1 rule.
        None => "exists",
    }
}

/// Queue a donation record in the inbox, returning its donation id.
pub fn enqueue(
    item_id: &str,
    consumer: &str,
    from: &str,
    item_kind: &str,
    armor: &str,
) -> Result<String> {
    let donation_id = crypto::random_token()?;
    let record = json!({
        "id": donation_id,
        "from": from,
        "consumer": consumer,
        "item_id": item_id,
        "kind": item_kind,
        "armor": armor,
        "received_at": now_iso(),
    });
    let mut inbox = load_inbox()?;
    inbox
        .get_mut("donations")
        .and_then(Value::as_array_mut)
        .context("inbox donations section")?
        .push(record);
    save_inbox(&inbox)?;
    Ok(donation_id)
}

fn take_donation(inbox: &mut Value, donation_id: &str) -> Result<Value> {
    let donations = inbox
        .get_mut("donations")
        .and_then(Value::as_array_mut)
        .context("inbox donations section")?;
    let position = donations
        .iter()
        .position(|d| d.get("id").and_then(Value::as_str) == Some(donation_id))
        .with_context(|| format!("no pending donation: {donation_id}"))?;
    Ok(donations.remove(position))
}

pub fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "donations" => {
            let inbox = load_inbox()?;
            let pending: Vec<Value> = inbox
                .get("donations")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|d| {
                    json!({
                        "id": d.get("id"),
                        "from": d.get("from"),
                        "consumer": d.get("consumer"),
                        "item_id": d.get("item_id"),
                        "kind": d.get("kind"),
                        "received_at": d.get("received_at"),
                    })
                })
                .collect();
            Ok(Some(json!(pending)))
        }
        "donation-accept" => {
            let donation_id = positionals
                .first()
                .context("usage: donation-accept <donation-id>")?;
            let mut inbox = load_inbox()?;
            let donation = take_donation(&mut inbox, donation_id)?;
            let item_id = donation
                .get("item_id")
                .and_then(Value::as_str)
                .context("donation has no item_id")?
                .to_string();
            let from = donation
                .get("from")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let armor = donation
                .get("armor")
                .and_then(Value::as_str)
                .context("donation has no armor")?;
            let mut vault = Vault::open(vault_path())?;
            // Re-apply the admission rule at merge time: the vault may have
            // changed since the donation was queued.
            let rule = admission(&vault, &item_id, &from);
            if rule != "append" && rule != "overwrite" {
                save_inbox(&inbox)?;
                crate::runtime::audit::append(
                    "donation-accept-refused",
                    &json!({"donation": donation_id, "item": item_id, "status": rule}),
                )?;
                return Ok(Some(
                    json!({"ok": false, "status": rule, "donation_id": donation_id, "id": item_id}),
                ));
            }
            let plain = crypto::decrypt(armor).context("decrypt donation armor")?;
            let payload: Value =
                serde_json::from_str(&plain).context("donation payload is not JSON")?;
            let existing = vault
                .doc()
                .get("items")
                .and_then(|items| items.get(&item_id))
                .cloned();
            let item_kind = donation
                .get("kind")
                .and_then(Value::as_str)
                .or_else(|| {
                    existing
                        .as_ref()
                        .and_then(|item| item.get("kind"))
                        .and_then(Value::as_str)
                })
                .context("donation has no canonical item kind")?
                .to_string();
            let recipients = vault.item_recipient_uids(&item_id);
            let tags: Vec<String> = existing
                .as_ref()
                .and_then(|item| item.get("tags"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
            vault.set_item_written_by(&item_id, &item_kind, &payload, &recipients, &tags, &from)?;
            save_inbox(&inbox)?;
            crate::runtime::audit::append(
                "donation-accept",
                &json!({"donation": donation_id, "item": item_id, "from": from, "rule": rule}),
            )?;
            Ok(Some(json!({
                "ok": true,
                "status": if rule == "overwrite" { "overwritten" } else { "merged" },
                "donation_id": donation_id,
                "id": item_id,
            })))
        }
        "donation-reject" => {
            let donation_id = positionals
                .first()
                .context("usage: donation-reject <donation-id>")?;
            let mut inbox = load_inbox()?;
            let donation = take_donation(&mut inbox, donation_id)?;
            save_inbox(&inbox)?;
            crate::runtime::audit::append(
                "donation-reject",
                &json!({"donation": donation_id, "item": donation.get("item_id")}),
            )?;
            Ok(Some(
                json!({"ok": true, "status": "rejected", "donation_id": donation_id}),
            ))
        }
        _ => Ok(None),
    }
}
