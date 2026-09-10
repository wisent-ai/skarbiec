// Reading what the vault holds and moving an item between live, trashed and
// gone. Every mutation here is refused for an item a lifecycle controls.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;
use crate::core::vault_path;

use super::args::{emit, flag_set};
use super::items::ensure_owner_mutation_allowed;


pub(crate) fn cmd_delete(positionals: &[String]) -> Result<Value> {
    let id = positionals.first().context("usage: delete <id>")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "remove")?;
    vault.delete_item(id)?;
    Ok(json!({"ok": true}))
}

pub(crate) fn cmd_reclaim(positionals: &[String]) -> Result<Value> {
    let id = positionals.first().context("usage: reclaim <id>")?;
    let mut vault = Vault::open(vault_path())?;
    vault.reclaim_item(id)?;
    Ok(json!({"ok": true, "id": id, "mode": "owner"}))
}

pub(crate) fn cmd_restore(positionals: &[String]) -> Result<Value> {
    let id = positionals.first().context("usage: restore <id>")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "acquire")?;
    vault.restore_item(id)?;
    Ok(json!({"ok": true}))
}

pub(crate) fn cmd_purge(positionals: &[String]) -> Result<Value> {
    let id = positionals.first().context("usage: purge <id>")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "remove")?;
    vault.purge_item(id)?;
    Ok(json!({"ok": true}))
}

pub(crate) fn cmd_restore_version(positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: restore-version <id> <at>")?;
    let at = positionals
        .get(std::iter::once(()).count())
        .context("usage: restore-version <id> <at>")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "rotate")?;
    vault.restore_version(id, at)?;
    emit(&json!({"ok": true}))
}

pub(crate) fn cmd_get(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: get <id> [--field <field>]")?;
    let item = Vault::open(vault_path())?.get_item(id)?;
    let Some(field) = flags.get("field") else {
        return emit(&item);
    };
    if field.is_empty() || field.chars().any(char::is_control) {
        bail!("get --field requires one exact field name");
    }
    let value = item
        .get("fields")
        .and_then(Value::as_object)
        .and_then(|fields| fields.get(field))
        .with_context(|| format!("item {id} has no field {field}"))?
        .as_str()
        .with_context(|| format!("item {id} field {field} is not text"))?;
    println!("{value}");
    Ok(())
}

pub(crate) fn cmd_list(flags: &HashMap<String, String>) -> Result<Value> {
    Ok(json!(
        Vault::open(vault_path())?.list(flag_set(flags, "all"))
    ))
}
