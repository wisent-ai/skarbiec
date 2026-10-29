// What one person can open: every item whose current ciphertext lists them,
// live and trashed, read from the cleartext envelope without decrypting
// anything. The question before an offboarding, an audit or a share review.

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::core::{vault::Vault, vault_path};

/// `recipient items <uid>`.
///
/// An unknown uid is refused naming the registered ones, because an empty
/// list would read as "this person can open nothing". Items whose recipient
/// list cannot be read are named with that error instead of being skipped.
pub(super) fn items_of(uid: &str) -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    if vault.recipient_fpr(uid).is_none() {
        let registered: Vec<&String> = vault
            .doc()
            .get("recipients")
            .and_then(Value::as_object)
            .context("the vault has no recipients section to look the uid up in")?
            .keys()
            .collect();
        return Err(crate::cli::args::Usage(format!(
            "unknown recipient: {uid}; the registered recipients are: {}",
            registered
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .into());
    }
    let mut live = Vec::new();
    let mut trashed = Vec::new();
    let mut unreadable = Vec::new();
    for item in vault.list(true) {
        let Some(id) = item.get("id").and_then(Value::as_str) else {
            continue;
        };
        match vault.item_recipient_uids(id) {
            Ok(readers) if readers.iter().any(|reader| reader == uid) => {
                if item.get("deleted") == Some(&Value::Bool(true)) {
                    trashed.push(id.to_string());
                } else {
                    live.push(id.to_string());
                }
            }
            Ok(_) => {}
            Err(error) => unreadable.push(json!({"item": id, "error": format!("{error:#}")})),
        }
    }
    Ok(json!({
        "ok": true,
        "uid": uid,
        "items": live,
        "trashed": trashed,
        "unreadable": unreadable,
    }))
}
