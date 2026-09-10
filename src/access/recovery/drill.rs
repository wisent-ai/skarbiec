// Proving recovery works before an incident: the deterministic canary a
// recipient must open, and the key report an operator reads beside it.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{crypto, vault_path};

use super::load;

pub(super) fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "recovery-drill" => {
            let expected = positionals
                .first()
                .context("usage: recovery-drill <recipient-uid|recovery>")?;
            let vault = load()?;
            let expected_fingerprint = if expected == "recovery" {
                vault.recovery_fpr().to_string()
            } else {
                vault
                    .recipient_fpr(expected)
                    .with_context(|| format!("unknown recovery drill recipient {expected}"))?
            };
            if !crypto::secret_key_present(&expected_fingerprint) {
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
                [fingerprint] if fingerprint == &expected_fingerprint => {}
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
        _ => Ok(None),
    }
}
