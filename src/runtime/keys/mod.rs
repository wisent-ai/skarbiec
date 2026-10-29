// The life of every key the vault writes to: each registered recipient's and
// the recovery key. An OpenPGP key can expire or be revoked; what was written
// to it still opens, but the next write to it fails, so a share, a rotation
// or a revoke that rewraps saved versions stops at that key. This says which
// keys are near that point while there is time to extend them.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{clock, crypto, vault::Vault, vault_path};

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    _positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "keys" => keys(flags).map(Some),
        _ => Ok(None),
    }
}

/// `skarbiec keys [--expiring-before <iso8601>]`: every key, or only the
/// ones that end before a moment (expired and revoked ones always count).
fn keys(flags: &HashMap<String, String>) -> Result<Value> {
    let before = flags.get("expiring-before");
    if let Some(before) = before {
        if !clock::is_iso(before) {
            return Err(crate::cli::args::Usage(format!(
                "--expiring-before {before} is not a UTC time of the form {}",
                clock::now_iso()
            ))
            .into());
        }
    }
    let vault = Vault::open(vault_path())?;
    let now = clock::now_iso();
    let mut named: Vec<(String, String)> = vault
        .doc()
        .get("recipients")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(uid, _)| vault.recipient_fpr(uid).map(|fpr| (uid.clone(), fpr)))
        .collect();
    let recovery = vault.recovery_fpr().to_string();
    if !recovery.is_empty() {
        named.push(("recovery".to_string(), recovery));
    }
    let mut rows = Vec::new();
    let mut unreadable = Vec::new();
    for (holder, fingerprint) in named {
        match crypto::key_validity(&fingerprint) {
            Ok(Some(validity)) => {
                let expires_at = validity.expires_epoch.and_then(clock::iso_at);
                let expired = validity.validity == "e"
                    || expires_at.as_deref().is_some_and(|at| at <= now.as_str());
                let revoked = validity.validity == "r";
                let ends_before = before.is_none_or(|before| {
                    expired || revoked || expires_at.as_deref().is_some_and(|at| at < before.as_str())
                });
                if ends_before {
                    rows.push(json!({
                        "holder": holder,
                        "fingerprint": fingerprint,
                        "in_keyring": true,
                        "expires_at": expires_at,
                        "expired": expired,
                        "revoked": revoked,
                        "repair": repair(&holder, vault.owner_uid()),
                    }));
                }
            }
            Ok(None) => rows.push(json!({
                "holder": holder,
                "fingerprint": fingerprint,
                "in_keyring": false,
                "expires_at": Value::Null,
                "expired": Value::Null,
                "revoked": Value::Null,
            })),
            Err(error) => unreadable.push(json!({"holder": holder, "fingerprint": fingerprint, "error": format!("{error:#}")})),
        }
    }
    let ok = unreadable.is_empty()
        && rows.iter().all(|row| {
            row["expired"] != json!(true)
                && row["revoked"] != json!(true)
                && row["in_keyring"] == json!(true)
        });
    Ok(
        json!({"ok": ok, "checked_at": now, "expiring_before": before, "keys": rows, "unreadable": unreadable}),
    )
}

/// The command that replaces a key that ended or is about to: a person's
/// with recipient rekey, the owner's with owner rotate. The recovery key is
/// kept offline, so extending it is said rather than named as a command.
fn repair(holder: &str, owner: &str) -> String {
    if holder == owner {
        return "extend the key with gpg --quick-set-expire, or move the vault to a new owner key with `skarbiec owner rotate <new-owner-uid>`".to_string();
    }
    if holder == "recovery" {
        return "extend the recovery key with gpg --quick-set-expire where it is kept offline, then import its public half here".to_string();
    }
    format!("extend the key with gpg --quick-set-expire, or give {holder} a new one with `skarbiec recipient rekey {holder} --import <public-key-file> --yes`")
}
