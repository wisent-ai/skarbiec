// Proving recovery works before an incident: the deterministic canary a
// recipient must open, and the key report an operator reads beside it.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{crypto, vault_path};

use super::load;
use crate::cli::args::OrUsage;

/// The command whose verbs this module answers (`recovery status|drill`).
pub(super) const GROUP: &str = "recovery";

pub(super) fn help() -> Value {
    json!({
        "commands": [
            "recovery status",
            "recovery drill <recipient-uid|recovery>",
        ],
        "usage": "recovery status reports the vault's recovery recipient and whether its secret key is in this host's key file; recovery drill proves that one expected recovery identity, in a key file holding only it (SKARBIEC_KEYS_FILE), can open the vault.",
    })
}

pub(super) fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "recovery drill" => {
            let expected = positionals
                .first()
                .or_usage("usage: recovery drill <recipient-uid|recovery>")?;
            let vault = load()?;
            let expected_fingerprint = if expected == "recovery" {
                vault.recovery_fpr().to_string()
            } else {
                vault
                    .recipient_fpr(expected)
                    .with_context(|| format!("unknown recovery drill recipient {expected}"))?
            };
            if !crypto::secret_key_present(&expected_fingerprint)? {
                anyhow::bail!(
                    "the key file {} does not hold the secret half of {expected} ({expected_fingerprint}); \
                     bring it in with `skarbiec keys import --gnupg-home <dir> --keys {expected_fingerprint}` \
                     into a key file of its own (SKARBIEC_KEYS_FILE) and drill again",
                    crypto::key_file().display()
                );
            }
            let mut local_openers: Vec<String> = Vec::new();
            for fingerprint in vault
                .section("recipients", "uid -> recipient")?
                .values()
                .filter_map(|entry| entry.get("fingerprint").and_then(Value::as_str))
            {
                if crypto::secret_key_present(fingerprint)? {
                    local_openers.push(fingerprint.to_string());
                }
            }
            let recovery = vault.recovery_fpr();
            if !recovery.is_empty()
                && crypto::secret_key_present(recovery)?
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
                    "recovery drill needs a key file holding only the expected vault opener, and {} \
                     holds the secret half of {}; point SKARBIEC_KEYS_FILE at a key file holding \
                     only {expected_fingerprint}",
                    crypto::key_file().display(),
                    local_openers.join(", ")
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
            let open_error = vault
                .get_item(canary)
                .err()
                .map(|error| format!("{error:#}"));
            let passed = open_error.is_none();
            crate::runtime::audit::append_sync(
                "recovery-drill",
                &json!({
                    "recipient": expected,
                    "fingerprint": expected_fingerprint,
                    "canary_item": canary,
                    "passed": passed,
                    "canary_error": open_error,
                }),
            )?;
            Ok(Some(json!({
                "status": if passed { "passed" } else { "failed" },
                "recipient": expected,
                "fingerprint": expected_fingerprint,
                "canary_item": canary,
                "canary_error": open_error,
                "isolated_keyring": true,
            })))
        }
        "recovery status" => {
            let vault = load()?;
            let items = vault.section("items", "id -> item")?.len();
            let fpr = vault.recovery_fpr().to_string();
            // Reporting the fingerprint proved nothing about recoverability:
            // this command answered identically whether the offline material
            // was in a safe or had never existed. It now says which.
            let held = !fpr.is_empty() && crypto::secret_key_present(&fpr)?;
            Ok(Some(json!({
                "recovery_fpr": fpr,
                "secret_half_present_locally": held,
                "note": if held {
                    "recovery secret half is in THIS host's key file, so it shares one failure domain with the owner key; offline material belongs off-machine"
                } else {
                    "recovery recipient is on every item; its offline material is the last way in — verify a drill can open one item"
                },
                "item_count": items,
            })))
        }
        "keys check" => {
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
                .section("recipients", "uid -> recipient")
                .context("keys check cannot say which key opens the vault")?
                .clone();
            for (uid, entry) in &registry {
                let role = entry.get("role").and_then(Value::as_str);
                // A recipient that records no fingerprint names no key: asking
                // the keyring about an empty fingerprint would answer for keys
                // that are not this recipient's.
                let Some(fpr) = entry
                    .get("fingerprint")
                    .and_then(Value::as_str)
                    .filter(|fpr| !fpr.is_empty())
                else {
                    recipients.push(json!({
                        "uid": uid,
                        "fingerprint": null,
                        "role": role,
                        "is_owner": uid == &owner,
                        "secret_half_present": false,
                        "damaged": "the vault document records no fingerprint for this recipient, so no key can be named for it",
                    }));
                    continue;
                };
                let held = crypto::secret_key_present(fpr)?;
                if held {
                    openers.push(uid.clone());
                }
                recipients.push(json!({
                    "uid": uid,
                    "fingerprint": fpr,
                    "role": role,
                    "is_owner": uid == &owner,
                    "secret_half_present": held,
                }));
            }
            if !recovery.is_empty()
                && !registry.values().any(|entry| {
                    entry.get("fingerprint").and_then(Value::as_str) == Some(recovery.as_str())
                })
            {
                let held = crypto::secret_key_present(&recovery)?;
                if held {
                    openers.push("recovery".to_string());
                }
                recipients.push(json!({
                    "uid": "recovery",
                    "fingerprint": recovery,
                    "role": "recovery",
                    "is_owner": false,
                    "secret_half_present": held,
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
            // Why the canary did not open is the evidence the remedy rests on:
            // a missing secret half reads differently from an agent that is
            // down or an item that is damaged.
            let open_error = match &canary {
                Some(id) => vault.get_item(id).err().map(|error| format!("{error:#}")),
                None => None,
            };
            let opened = canary.is_some() && open_error.is_none();
            let readable = if canary.is_none() {
                "empty"
            } else if opened {
                "readable"
            } else {
                "unreadable"
            };
            Ok(Some(json!({
                "vault": vault_path().display().to_string(),
                // Named even when a secret half is present: this is the file
                // an operator has to back up apart from the vault, not only
                // restore.
                "key_file": crypto::key_file().display().to_string(),
                "owner": owner,
                "status": readable,
                "canary_item": canary,
                "canary_error": open_error,
                "keys_that_could_open_it": openers,
                "recipients": recipients,
                "remedy": if opened || canary.is_none() {
                    Value::Null
                } else {
                    json!("the canary item could not be decrypted: inspect canary_error and the recipient key inventory before choosing key restoration or owner rotation")
                },
            })))
        }
        _ => Ok(None),
    }
}
