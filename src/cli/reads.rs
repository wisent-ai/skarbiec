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

/// `skarbiec duplicates`: which active items hold exactly the same payload.
///
/// A write now refuses a second holder of one payload, so this answers the
/// question for everything written before that refusal existed — on this
/// fleet, a vault where one platform appears as `oxylabs`,
/// `platform-admin-oxylabs` and `weles-oxylabs-dashboard-login`. It decrypts
/// nothing: the comparison is the fingerprint each envelope carries.
pub(crate) fn cmd_duplicates() -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    let groups = vault.duplicate_groups();
    let (active, unstamped) = vault.duplicate_coverage();
    let items: usize = groups
        .iter()
        .filter_map(|group| group.get("items"))
        .filter_map(|ids| ids.as_array().map(Vec::len))
        .sum();
    let mut report = json!({
        "groups": groups.len(),
        "items": items,
        "active_items": active,
        "compared": active - unstamped,
        "without_fingerprint": unstamped,
        "duplicates": groups,
    });
    if unstamped > 0 {
        report["note"] = json!(format!(
            "{unstamped} of {active} active items were written before payload fingerprints \
             existed and cannot be compared with anything; each one is stamped by the next \
             `skarbiec set` of that item, so an empty duplicate list over this vault means \
             nothing comparable rather than nothing duplicated"
        ));
    }
    Ok(report)
}

/// `skarbiec stamp-fingerprints [--apply]`: describe the items that predate
/// the payload fingerprint so the duplicate report and the write refusal
/// cover the whole vault.
///
/// Without `--apply` it reports what the pass would stamp and which items it
/// cannot read. It never rewrites a payload: the ciphertext, the revision and
/// the history of every item stay as they are.
pub(crate) fn cmd_stamp_fingerprints(flags: &HashMap<String, String>) -> Result<Value> {
    let apply = flags.contains_key("apply");
    Vault::open(vault_path())?.stamp_fingerprints(apply)
}
