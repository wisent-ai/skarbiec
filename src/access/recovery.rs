// Recovery + emergency access.
//
// Recovery: the recovery recipient is on every item (see core::vault), so
// losing the day-to-day identity never loses data — the offline recovery
// material still opens everything. `recovery-status` reports it.
//
// Emergency access: grant a registered user access that becomes active only at
// or after an operator-set timestamp, unless cancelled first. Activation shares
// every live item with the grantee by re-encrypting to include their identity.
// Timestamps are ISO-8601 and compared as strings (which sorts chronologically),
// so there is no numeric time arithmetic here.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;

use crate::core::{crypto, vault::Vault, vault_path};

fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

fn now_iso() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn ensure_section<'a>(doc: &'a mut Value, key: &str) -> &'a mut serde_json::Map<String, Value> {
    let object = doc.as_object_mut().expect("vault doc is object");
    object.entry(key).or_insert_with(|| json!({}));
    object
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .expect("section is object")
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "recovery-drill" => {
            let expected = positionals
                .first()
                .context("usage: recovery-drill <recipient-uid|recovery>")?;
            let vault = load()?;
            let expected_fingerprint = if expected == "recovery" {
                vault.recovery_fpr()
            } else {
                vault
                    .recipient_fpr(expected)
                    .with_context(|| format!("unknown recovery drill recipient {expected}"))?
            };
            if !crypto::secret_key_present(expected_fingerprint) {
                anyhow::bail!("expected recovery secret half is absent from this keyring");
            }
            let mut local_openers: Vec<String> = vault
                .doc()
                .get("recipients")
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|recipients| recipients.values())
                .filter_map(|entry| entry.get("fingerprint").and_then(Value::as_str))
                .filter(|fingerprint| crypto::secret_key_present(fingerprint))
                .map(str::to_string)
                .collect();
            let recovery = vault.recovery_fpr();
            if !recovery.is_empty()
                && crypto::secret_key_present(recovery)
                && !local_openers
                    .iter()
                    .any(|fingerprint| fingerprint == recovery)
            {
                local_openers.push(recovery.to_string());
            }
            local_openers.sort();
            local_openers.dedup();
            match local_openers.as_slice() {
                [fingerprint] if fingerprint == expected_fingerprint => {}
                _ => anyhow::bail!(
                    "recovery drill requires an isolated keyring containing only the expected vault opener"
                ),
            }
            let mut ids: Vec<String> = vault
                .list(false)
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
                .collect();
            ids.sort();
            let canary = ids
                .first()
                .context("recovery drill requires at least one live item")?;
            let passed = vault.get_item(canary).is_ok();
            crate::runtime::audit::append_sync(
                "recovery-drill",
                &json!({
                    "recipient": expected,
                    "fingerprint": expected_fingerprint,
                    "canary_item": canary,
                    "passed": passed,
                }),
            )?;
            Ok(Some(json!({
                "status": if passed { "passed" } else { "failed" },
                "recipient": expected,
                "fingerprint": expected_fingerprint,
                "canary_item": canary,
                "isolated_keyring": true,
            })))
        }
        "recovery-status" => {
            let vault = load()?;
            let items = vault
                .doc()
                .get("items")
                .and_then(Value::as_object)
                .map(|m| m.len())
                .unwrap_or_default();
            let fpr = vault.recovery_fpr().to_string();
            // Reporting the fingerprint proved nothing about recoverability:
            // this command answered identically whether the offline material
            // was in a safe or had never existed. It now says which.
            let held = !fpr.is_empty() && crypto::secret_key_present(&fpr);
            Ok(Some(json!({
                "recovery_fpr": fpr,
                "secret_half_present_locally": held,
                "note": if held {
                    "recovery secret half is in THIS keyring, so it shares one failure domain with the owner key; offline material belongs off-machine"
                } else {
                    "recovery recipient is on every item; its offline material is the last way in — verify a drill can open one item"
                },
                "item_count": items,
            })))
        }
        "key-doctor" => {
            // The question every outage asks and nothing could answer: can any
            // key on this machine still open the vault, and if not, exactly
            // which file has to come back from backup. Reads the vault document
            // and the keyring directly, never the HTTP API — the API is the
            // first thing that stops working, and a diagnosis that needs the
            // patient healthy is not a diagnosis.
            let vault = load()?;
            let owner = vault.owner_uid().to_string();
            let recovery = vault.recovery_fpr().to_string();
            let mut recipients = Vec::new();
            let mut openers = Vec::new();
            let registry = vault
                .doc()
                .get("recipients")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            for (uid, entry) in &registry {
                let fpr = entry
                    .get("fingerprint")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let held = !fpr.is_empty() && crypto::secret_key_present(fpr);
                if held {
                    openers.push(uid.clone());
                }
                let grips = crypto::keygrips_for(fpr);
                recipients.push(json!({
                    "uid": uid,
                    "fingerprint": fpr,
                    "role": entry.get("role").and_then(Value::as_str).unwrap_or_default(),
                    "is_owner": uid == &owner,
                    "secret_half_present": held,
                    "keygrips": grips.clone(),
                    // Named even when the secret half is present: this is the
                    // path an operator has to back up, not only restore.
                    "key_files": grips
                        .iter()
                        .map(|grip| json!(format!("private-keys-v1.d/{grip}.key")))
                        .collect::<Vec<Value>>(),
                }));
            }
            if !recovery.is_empty()
                && !registry.values().any(|entry| {
                    entry.get("fingerprint").and_then(Value::as_str) == Some(recovery.as_str())
                })
            {
                let held = crypto::secret_key_present(&recovery);
                if held {
                    openers.push("recovery".to_string());
                }
                let grips = crypto::keygrips_for(&recovery);
                recipients.push(json!({
                    "uid": "recovery",
                    "fingerprint": recovery,
                    "role": "recovery",
                    "is_owner": false,
                    "secret_half_present": held,
                    "keygrips": grips.clone(),
                    "key_files": grips
                        .iter()
                        .map(|grip| json!(format!("private-keys-v1.d/{grip}.key")))
                        .collect::<Vec<Value>>(),
                }));
            }
            // The only proof that survives argument: open something. The lowest
            // live id is deterministic, so repeated runs exercise one item, and
            // the plaintext is dropped here.
            let mut ids: Vec<String> = vault
                .list(false)
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
                .collect();
            ids.sort();
            let canary = ids.first().cloned();
            let opened = match &canary {
                Some(id) => vault.get_item(id).map(|_| true).unwrap_or(false),
                None => false,
            };
            let readable = if canary.is_none() {
                "empty"
            } else if opened {
                "readable"
            } else {
                "unreadable"
            };
            Ok(Some(json!({
                "vault": vault_path().display().to_string(),
                "owner": owner,
                "status": readable,
                "canary_item": canary,
                "keys_that_could_open_it": openers,
                "recipients": recipients,
                "remedy": if opened || canary.is_none() {
                    Value::Null
                } else {
                    json!("no secret half on this machine opens the vault: restore one recipient's key_files into ~/.gnupg/, then rotate-owner onto a key you hold")
                },
            })))
        }
        "emergency-grant" => {
            let grantee = positionals
                .first()
                .context("usage: emergency-grant <grantee> --activate-after <iso>")?;
            let activate_after = flags
                .get("activate-after")
                .context("--activate-after <iso8601> required")?;
            let mut vault = load()?;
            if vault.recipient_fpr(grantee).is_none() {
                return Ok(Some(
                    json!({"status": "blocked", "reason": "unknown_recipient", "grantee": grantee}),
                ));
            }
            let stamp = now_iso();
            ensure_section(vault.doc_mut(), "emergency").insert(
                grantee.clone(),
                json!({
                    "activate_after": activate_after,
                    "granted_at": stamp,
                    "status": "pending",
                }),
            );
            vault.save()?;
            crate::runtime::audit::append(
                "emergency-grant",
                &json!({"grantee": grantee, "activate_after": activate_after}),
            )?;
            Ok(Some(
                json!({"ok": true, "grantee": grantee, "activate_after": activate_after}),
            ))
        }
        "emergency-cancel" => {
            let grantee = positionals
                .first()
                .context("usage: emergency-cancel <grantee>")?;
            let mut vault = load()?;
            ensure_section(vault.doc_mut(), "emergency").remove(grantee);
            vault.save()?;
            crate::runtime::audit::append("emergency-cancel", &json!({"grantee": grantee}))?;
            Ok(Some(json!({"ok": true, "grantee": grantee})))
        }
        "emergency-list" => {
            let vault = load()?;
            Ok(Some(
                vault
                    .doc()
                    .get("emergency")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
            ))
        }
        "emergency-activate" => {
            let grantee = positionals
                .first()
                .context("usage: emergency-activate <grantee>")?;
            let mut vault = load()?;
            let activate_after = vault
                .doc()
                .get("emergency")
                .and_then(|e| e.get(grantee))
                .and_then(|g| g.get("activate_after"))
                .and_then(Value::as_str)
                .with_context(|| format!("no emergency grant for {grantee}"))?
                .to_string();
            let current = now_iso();
            if current < activate_after {
                return Ok(Some(
                    json!({"status": "not_yet", "grantee": grantee, "activate_after": activate_after, "now": current}),
                ));
            }
            let ids: Vec<String> = vault
                .doc()
                .get("items")
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter(|(_, it)| {
                            !it.get("deleted").and_then(Value::as_bool).unwrap_or(false)
                        })
                        .map(|(id, _)| id.clone())
                        .collect()
                })
                .unwrap_or_default();
            let mut shared = Vec::new();
            for id in &ids {
                let item = vault
                    .doc()
                    .get("items")
                    .and_then(|m| m.get(id))
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let item_type = item
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("login")
                    .to_string();
                let tags: Vec<String> = item
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let secret = vault.get_item(id)?;
                let mut recipients = vault.item_recipient_uids(id);
                if !recipients.iter().any(|r| r == grantee) {
                    recipients.push(grantee.clone());
                }
                vault.set_item(id, &item_type, &secret, &recipients, &tags)?;
                shared.push(id.clone());
            }
            ensure_section(vault.doc_mut(), "emergency")
                .get_mut(grantee)
                .and_then(Value::as_object_mut)
                .context("emergency entry")?
                .insert("status".to_string(), json!("activated"));
            vault.save()?;
            crate::runtime::audit::append(
                "emergency-activate",
                &json!({"grantee": grantee, "items": shared.len()}),
            )?;
            Ok(Some(
                json!({"ok": true, "grantee": grantee, "shared_items": shared}),
            ))
        }
        _ => Ok(None),
    }
}
