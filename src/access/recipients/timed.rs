// Shares that end on their own: `share <item> <uid> --until <iso8601>`
// records when that person stops reading the item, and `shares expire` —
// run by every `maintain` pass on the vault's owner — revokes each share
// whose moment has passed, exactly as `revoke` would, saved versions
// included. Until then the share is an ordinary one.

use anyhow::{bail, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::core::{clock, vault::Vault, vault_path};

/// The vault section: item id -> recipient uid -> the moment the share ends.
const SECTION: &str = "share_until";

/// The `--until` a share asks for, checked: a stamp of the vault's form and
/// still ahead, since a share that ended before it began is a mistake, not a
/// share. None when the flag is not given.
pub(super) fn checked(flags: &HashMap<String, String>) -> Result<Option<String>> {
    let Some(until) = flags.get("until") else {
        return Ok(None);
    };
    let now = clock::now_iso();
    if !clock::is_iso(until) {
        return Err(crate::cli::args::Usage(format!("--until {until} is not a UTC time of the form {now}")).into());
    }
    if until.as_str() <= now.as_str() {
        bail!("--until {until} has already passed (it is {now}); name a moment ahead");
    }
    Ok(Some(until.clone()))
}

/// Record `--until` for one share, saving the vault, when the flag is given.
pub(super) fn apply(vault: &mut Vault, item: &str, uid: &str, flags: &HashMap<String, String>) -> Result<Option<String>> {
    let Some(until) = checked(flags)? else {
        return Ok(None);
    };
    let section = vault
        .doc_mut()
        .as_object_mut()
        .map(|doc| doc.entry(SECTION.to_string()).or_insert_with(|| json!({})));
    let Some(Value::Object(section)) = section else {
        bail!("the vault's {SECTION} section is not an object of items");
    };
    let readers = section.entry(item.to_string()).or_insert_with(|| json!({}));
    let Value::Object(readers) = readers else {
        bail!("the vault's {SECTION} entry for {item} is not an object of recipients");
    };
    readers.insert(uid.to_string(), json!(until));
    vault.save()?;
    Ok(Some(until))
}

/// Forget the end of one share; the caller saves. A share revoked by hand
/// has nothing left to expire.
pub(super) fn forget(vault: &mut Vault, item: &str, uid: &str) {
    let Some(section) = vault.doc_mut().get_mut(SECTION).and_then(Value::as_object_mut) else {
        return;
    };
    if let Some(readers) = section.get_mut(item).and_then(Value::as_object_mut) {
        readers.remove(uid);
        if readers.is_empty() {
            section.remove(item);
        }
    }
}

/// Carry the ends recorded for `from` over to `to` after a rename, so a
/// share that was to end still ends; the caller saves. True when there were
/// any to carry.
pub fn follow_rename(vault: &mut Vault, from: &str, to: &str) -> bool {
    let Some(section) = vault.doc_mut().get_mut(SECTION).and_then(Value::as_object_mut) else {
        return false;
    };
    match section.remove(from) {
        Some(readers) => {
            section.insert(to.to_string(), readers);
            true
        }
        None => false,
    }
}

/// Every recorded end, soonest first, with whether it has passed.
fn rows(vault: &Vault, now: &str) -> Vec<Value> {
    let empty = Map::new();
    let section = match vault.doc().get(SECTION).and_then(Value::as_object) {
        Some(section) => section,
        None => &empty,
    };
    let mut rows: Vec<Value> = section
        .iter()
        .flat_map(|(item, readers)| {
            readers
                .as_object()
                .into_iter()
                .flatten()
                .filter_map(move |(uid, until)| {
                    until.as_str().map(|until| {
                        json!({"item": item, "uid": uid, "until": until, "ended": until <= now})
                    })
                })
        })
        .collect();
    rows.sort_by(|a, b| a["until"].as_str().cmp(&b["until"].as_str()));
    rows
}

/// `shares` lists the timed shares; `shares expire` revokes the ended ones.
pub(super) fn dispatch(positionals: &[String]) -> Result<Value> {
    match positionals.first().map(String::as_str) {
        None => {
            let vault = Vault::open(vault_path())?;
            Ok(json!({"ok": true, "shares": rows(&vault, &clock::now_iso())}))
        }
        Some("expire") => expire(),
        Some(other) => Err(crate::cli::args::Usage(format!(
            "unknown shares command: {other}; `shares` lists the timed shares and `shares expire` revokes the ended ones"
        ))
        .into()),
    }
}

/// Revoke every share whose end has passed. A share whose item or reader is
/// already gone is forgotten and named as such; one that cannot be revoked
/// is reported with its error and kept, so the next pass tries again.
pub fn expire() -> Result<Value> {
    let mut vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_not_replica(&vault, "shares expire")?;
    let now = clock::now_iso();
    let mut revoked = Vec::new();
    let mut already_gone = Vec::new();
    let mut failed = Vec::new();
    for row in rows(&vault, &now).into_iter().filter(|row| row["ended"] == json!(true)) {
        let (Some(item), Some(uid)) = (row["item"].as_str(), row["uid"].as_str()) else {
            continue;
        };
        // A purged item has no readers left to revoke; any other failure to
        // read its recipients is reported and the share kept for next pass.
        let present = vault.doc().get("items").and_then(|items| items.get(item)).is_some();
        let reads = if present {
            match vault.item_recipient_uids(item) {
                Ok(readers) => readers.iter().any(|reader| reader == uid),
                Err(error) => {
                    failed.push(json!({"item": item, "uid": uid, "error": format!("{error:#}")}));
                    continue;
                }
            }
        } else {
            false
        };
        if !reads {
            forget(&mut vault, item, uid);
            already_gone.push(row);
            continue;
        }
        match vault.withdraw_recipient(uid, &[item.to_string()]) {
            Ok(_) => {
                forget(&mut vault, item, uid);
                revoked.push(row);
            }
            Err(error) => failed.push(json!({"item": item, "uid": uid, "error": format!("{error:#}")})),
        }
    }
    if !revoked.is_empty() || !already_gone.is_empty() {
        vault.save()?;
        crate::runtime::audit::append(
            "shares-expired",
            &json!({"revoked": revoked, "already_gone": already_gone}),
        )?;
    }
    Ok(json!({"ok": failed.is_empty(), "revoked": revoked, "already_gone": already_gone, "failed": failed}))
}
