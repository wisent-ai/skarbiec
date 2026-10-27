// The items reached for most — the bank, the work account, the router — kept
// at the front: `pin add <id>` puts one on the list, `pin remove <id>` takes
// it off, and `pin list` names them in the order they were pinned. The list
// is the vault's own metadata in the `pinned_items` section, beside
// item_expiry, so reading it opens no item; the desktop shows pinned items
// first and the menu bar's quick copies start with them. Rename carries a
// pin to the new id and purge forgets it.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::Usage;
use crate::core::{vault::Vault, vault_path};

/// The vault section: the pinned item ids, oldest pin first.
const SECTION: &str = "pinned_items";
const USAGE: &str = "usage: pin add <id> | pin remove <id> | pin list";

pub fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "pin" {
        return Ok(None);
    }
    let answer = match positionals {
        [verb, id] if verb == "add" => add(id)?,
        [verb, id] if verb == "remove" => remove(id)?,
        [verb] if verb == "list" => list()?,
        _ => return Err(Usage(USAGE.to_string()).into()),
    };
    Ok(Some(answer))
}

/// The pinned ids as the vault records them, oldest pin first; `list
/// --pinned` narrows to them.
pub(crate) fn pinned(vault: &Vault) -> Vec<String> {
    vault
        .doc()
        .get(SECTION)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn store(vault: &mut Vault, ids: &[String]) -> Result<()> {
    vault
        .doc_mut()
        .as_object_mut()
        .context("the vault document is not an object")?
        .insert(SECTION.to_string(), json!(ids));
    Ok(())
}

fn live_ids(vault: &Vault) -> Vec<String> {
    vault
        .list(false)
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
        .collect()
}

/// Pin one live item; one already pinned answers pinned false and nothing
/// is written.
pub fn add(id: &str) -> Result<Value> {
    let mut vault = Vault::open(vault_path())?;
    if !live_ids(&vault).iter().any(|live| live == id) {
        return Err(Usage(format!("{id} is not a live item, so it was not pinned; skarbiec list names the live ones")).into());
    }
    let mut ids = pinned(&vault);
    if ids.iter().any(|held| held == id) {
        return Ok(json!({"ok": true, "item": id, "pinned": false}));
    }
    ids.push(id.to_string());
    store(&mut vault, &ids)?;
    vault.save()?;
    crate::runtime::audit::append("item-pinned", &json!({"item": id}))?;
    Ok(json!({"ok": true, "item": id, "pinned": true}))
}

/// Unpin one item; one not pinned answers unpinned false and nothing is
/// written.
pub fn remove(id: &str) -> Result<Value> {
    let mut vault = Vault::open(vault_path())?;
    let ids = pinned(&vault);
    let kept: Vec<String> = ids.iter().filter(|held| *held != id).cloned().collect();
    if kept.len() == ids.len() {
        return Ok(json!({"ok": true, "item": id, "unpinned": false}));
    }
    store(&mut vault, &kept)?;
    vault.save()?;
    crate::runtime::audit::append("item-unpinned", &json!({"item": id}))?;
    Ok(json!({"ok": true, "item": id, "unpinned": true}))
}

/// Every pin, oldest first, each with whether its item is still live — a
/// trashed one stays pinned so restoring it brings it back to the front.
pub fn list() -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    let live = live_ids(&vault);
    let rows: Vec<Value> = pinned(&vault)
        .into_iter()
        .map(|id| {
            let is_live = live.iter().any(|known| *known == id);
            json!({"item": id, "live": is_live})
        })
        .collect();
    Ok(json!(rows))
}

/// Carry a pin to an item's new id after a rename, in place; the caller
/// saves. True when there was one.
pub fn follow_rename(vault: &mut Vault, from: &str, to: &str) -> Result<bool> {
    let ids = pinned(vault);
    if !ids.iter().any(|held| held == from) {
        return Ok(false);
    }
    let moved: Vec<String> = ids
        .into_iter()
        .map(|held| if held == from { to.to_string() } else { held })
        .collect();
    store(vault, &moved)?;
    Ok(true)
}

/// Drop a purged item's pin; the caller saves. True when there was one.
pub fn forget(vault: &mut Vault, id: &str) -> Result<bool> {
    let ids = pinned(vault);
    let kept: Vec<String> = ids.iter().filter(|held| *held != id).cloned().collect();
    if kept.len() == ids.len() {
        return Ok(false);
    }
    store(vault, &kept)?;
    Ok(true)
}
