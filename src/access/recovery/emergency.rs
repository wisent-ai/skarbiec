// Emergency access: a grant that waits out its delay in the open, can be
// cancelled while it waits, is activated only when the wait is over, and is
// revoked once activated. Activation records the items it added the grantee
// to, so revocation takes back exactly those and nothing the grantee was
// given some other way.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{ensure_section, load, now_iso};
use crate::cli::args::{OrUsage, Usage};
use crate::core::vault::Vault;

mod revoke;

/// The state a grant records: `pending` until activated, then `activated`.
const PENDING: &str = "pending";
const ACTIVATED: &str = "activated";

/// The command whose verbs this module answers (`emergency list|grant|...`).
pub(super) const GROUP: &str = "emergency";

pub(super) fn help() -> Value {
    json!({
        "commands": [
            "emergency list",
            "emergency grant <grantee> --activate-after <iso8601>",
            "emergency cancel <grantee>",
            "emergency activate <grantee>",
            "emergency revoke <grantee>",
        ],
        "usage": "An emergency grant waits out its delay in the open: emergency grant records a pending grant for one recipient, emergency cancel withdraws it while it waits, emergency activate shares every live item with the grantee once it is due and records which items it added them to, emergency revoke takes the grantee off exactly those items, every saved version included, and emergency list prints them all.",
    })
}

pub(super) fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "emergency grant" => grant(flags, positionals).map(Some),
        "emergency cancel" => cancel(positionals).map(Some),
        "emergency list" => list().map(Some),
        "emergency activate" => activate(positionals).map(Some),
        "emergency revoke" => revoke::revoke(positionals).map(Some),
        _ => Ok(None),
    }
}

/// The vault's `emergency` object; a vault that never granted emergency
/// access holds none, and a section of another shape is damage, said as such.
fn grants(vault: &Vault) -> Result<serde_json::Map<String, Value>> {
    match vault.doc().get("emergency") {
        None => Ok(serde_json::Map::new()),
        Some(Value::Object(grants)) => Ok(grants.clone()),
        Some(other) => {
            bail!("the vault document's emergency section is {other}, not an object of grants")
        }
    }
}

/// `emergency list`: every grant as recorded, and for a pending one whether
/// its delay has passed (`due`), so the list says which grants activate now
/// without the reader comparing stamps against the clock by hand.
fn list() -> Result<Value> {
    let now = now_iso();
    let mut grants = grants(&load()?)?;
    for grant in grants.values_mut() {
        let pending = status_of(grant) == PENDING;
        let due = pending
            && grant
                .get("activate_after")
                .and_then(Value::as_str)
                .is_some_and(|after| after <= now.as_str());
        if let Some(entry) = grant.as_object_mut() {
            entry.insert("due".to_string(), json!(due));
        }
    }
    Ok(Value::Object(grants))
}

/// One grantee's grant, or a refusal naming the grantees that do have one.
fn grant_of(vault: &Vault, grantee: &str, verb: &str) -> Result<Value> {
    let grants = grants(vault)?;
    if let Some(grant) = grants.get(grantee) {
        return Ok(grant.clone());
    }
    let held: Vec<&str> = grants.keys().map(String::as_str).collect();
    if held.is_empty() {
        bail!("no emergency grant for {grantee}: the vault holds no emergency grant, so there is nothing to {verb}; `skarbiec emergency grant {grantee} --activate-after <iso8601>` records one");
    }
    bail!(
        "no emergency grant for {grantee}, so there is nothing to {verb}; the vault holds grants for: {}",
        held.join(", ")
    )
}

/// The recorded state of a grant. A grant written before states were
/// recorded carries none and is read as pending, which is what it was
/// written as.
fn status_of(grant: &Value) -> &str {
    match grant.get("status").and_then(Value::as_str) {
        Some(status) => status,
        None => PENDING,
    }
}

fn grant(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let grantee = positionals
        .first()
        .or_usage("usage: emergency grant <grantee> --activate-after <iso8601>")?;
    let activate_after = flags
        .get("activate-after")
        .or_usage("--activate-after <iso8601> required")?;
    // Grants are compared with the clock as text, which orders them in time
    // only when both have the same shape; any other value would activate at
    // a moment it does not name, or never.
    if !crate::core::clock::is_iso(activate_after) {
        return Err(Usage(format!(
            "--activate-after {activate_after} is not a UTC time of the form {}; nothing was recorded",
            now_iso()
        ))
        .into());
    }
    let mut vault = load()?;
    if vault.recipient_fpr(grantee).is_none() {
        return Ok(json!({"status": "blocked", "reason": "unknown_recipient", "grantee": grantee}));
    }
    // A grant already activated has shared items; replacing its record with
    // a pending one would forget which, and `emergency revoke` could then no
    // longer take them back.
    let previous = grants(&vault)?.get(grantee).cloned();
    if let Some(previous) = &previous {
        if status_of(previous) == ACTIVATED {
            bail!(
                "the emergency grant for {grantee} is already activated; `skarbiec emergency revoke {grantee}` takes back the items it shared before a new grant is recorded"
            );
        }
    }
    let stamp = now_iso();
    ensure_section(vault.doc_mut(), "emergency")?.insert(
        grantee.clone(),
        json!({
            "activate_after": activate_after,
            "granted_at": stamp,
            "status": PENDING,
        }),
    );
    vault.save()?;
    let replaced = previous
        .as_ref()
        .and_then(|grant| grant.get("activate_after"))
        .cloned();
    crate::runtime::audit::append(
        "emergency-grant",
        &json!({"grantee": grantee, "activate_after": activate_after, "replaced_activate_after": replaced}),
    )?;
    Ok(json!({
        "ok": true,
        "grantee": grantee,
        "activate_after": activate_after,
        "replaced_activate_after": replaced,
    }))
}

fn cancel(positionals: &[String]) -> Result<Value> {
    let grantee = positionals
        .first()
        .or_usage("usage: emergency cancel <grantee>")?;
    let mut vault = load()?;
    let grant = grant_of(&vault, grantee, "cancel")?;
    // Cancelling an activated grant would delete its record and leave every
    // item it shared readable by the grantee, with nothing left to say so.
    if status_of(&grant) == ACTIVATED {
        bail!(
            "the emergency grant for {grantee} is already activated, and cancel withdraws only a grant that is still waiting; `skarbiec emergency revoke {grantee}` takes back the items its activation shared"
        );
    }
    ensure_section(vault.doc_mut(), "emergency")?.remove(grantee);
    vault.save()?;
    crate::runtime::audit::append("emergency-cancel", &json!({"grantee": grantee}))?;
    Ok(json!({"ok": true, "grantee": grantee}))
}

fn activate(positionals: &[String]) -> Result<Value> {
    let grantee = positionals
        .first()
        .or_usage("usage: emergency activate <grantee>")?;
    let mut vault = load()?;
    let grant = grant_of(&vault, grantee, "activate")?;
    // Activating twice must not share again: the first activation is the
    // answer, with the items it shared.
    if status_of(&grant) == ACTIVATED {
        return Ok(json!({
            "ok": true,
            "grantee": grantee,
            "already_activated": true,
            "activated_at": grant.get("activated_at"),
            "shared_items": grant.get("shared_items"),
            "added_to": grant.get("added_to"),
        }));
    }
    let activate_after = grant
        .get("activate_after")
        .and_then(Value::as_str)
        .with_context(|| format!("the emergency grant for {grantee} records no activate_after"))?
        .to_string();
    let current = now_iso();
    if current < activate_after {
        return Ok(
            json!({"status": "not_yet", "grantee": grantee, "activate_after": activate_after, "now": current}),
        );
    }
    // A vault document without an items object is damaged, not empty:
    // activating on it would mark the grant activated with nothing shared.
    let items = match vault.doc().get("items") {
        Some(Value::Object(items)) => items,
        other => bail!(
            "the vault document's items section is {}, not an object of id -> item; the emergency grant for {grantee} was not activated",
            match other {
                None => "missing".to_string(),
                Some(value) => value.to_string(),
            }
        ),
    };
    let ids: Vec<String> = items
        .iter()
        .filter(|(_, item)| item.get("state").and_then(Value::as_str) == Some("active"))
        .map(|(id, _)| id.clone())
        .collect();
    let mut shared = Vec::new();
    // The items the grantee could not read before: the only ones `emergency
    // revoke` takes back, so an item shared with them on purpose stays theirs.
    let mut added_to = Vec::new();
    for id in &ids {
        let item = vault
            .doc()
            .get("items")
            .and_then(|m| m.get(id))
            .cloned()
            .with_context(|| format!("active item {id} is no longer in the vault document"))?;
        let item_kind = item
            .get("kind")
            .and_then(Value::as_str)
            .context("canonical item has no kind")?
            .to_string();
        let tags = crate::core::vault::entry_texts(id, &item, "tags")
            .with_context(|| format!("the emergency grant for {grantee} was not activated"))?;
        let mut recipients = vault.item_recipient_uids(id)?;
        if !recipients.iter().any(|recipient| recipient == grantee) {
            let payload = vault.get_item(id)?;
            recipients.push(grantee.clone());
            vault.set_item(id, &item_kind, &payload, &recipients, &tags)?;
            added_to.push(id.clone());
        }
        shared.push(id.clone());
    }
    let stamp = now_iso();
    let entry = ensure_section(vault.doc_mut(), "emergency")?
        .get_mut(grantee)
        .and_then(Value::as_object_mut)
        .context("emergency entry")?;
    entry.insert("status".to_string(), json!(ACTIVATED));
    entry.insert("activated_at".to_string(), json!(stamp));
    entry.insert("shared_items".to_string(), json!(shared));
    entry.insert("added_to".to_string(), json!(added_to));
    vault.save()?;
    crate::runtime::audit::append(
        "emergency-activate",
        &json!({"grantee": grantee, "items": shared.len(), "added_to": added_to.len()}),
    )?;
    Ok(json!({
        "ok": true,
        "grantee": grantee,
        "activated_at": stamp,
        "shared_items": shared,
        "added_to": added_to,
    }))
}
