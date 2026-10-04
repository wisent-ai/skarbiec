// Reading what the vault holds and moving an item between live, trashed and
// gone. Every mutation here is refused for an item a lifecycle controls.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;
use crate::core::vault_path;

use super::args::{emit, flag_set, OrUsage};
use super::items::ensure_owner_mutation_allowed;

pub(crate) fn cmd_delete(positionals: &[String]) -> Result<Value> {
    let id = positionals.first().or_usage("usage: delete <id>")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "remove")?;
    vault.delete_item(id)?;
    Ok(json!({"ok": true}))
}

pub(crate) fn cmd_reclaim(positionals: &[String]) -> Result<Value> {
    let id = positionals.first().or_usage("usage: reclaim <id>")?;
    let mut vault = Vault::open(vault_path())?;
    vault.reclaim_item(id)?;
    Ok(json!({"ok": true, "id": id, "mode": "owner"}))
}

pub(crate) fn cmd_restore(positionals: &[String]) -> Result<Value> {
    let id = positionals.first().or_usage("usage: restore <id>")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "acquire")?;
    vault.restore_item(id)?;
    Ok(json!({"ok": true}))
}

/// Remove an item and every saved version for good. Nothing undoes it, so the
/// CLI needs `--yes` (`confirmed`); the operator API passes `true` because the
/// desktop's own Purge Permanently dialog is the confirmation it sends.
pub(crate) fn cmd_purge(positionals: &[String], confirmed: bool) -> Result<Value> {
    let id = positionals.first().or_usage("usage: purge <id> --yes")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "remove")?;
    if !confirmed {
        bail!(
            "purge would remove {id} and every saved version of it for good; nothing was removed. \
             Rerun with --yes to purge it, or restore {id} to keep it"
        );
    }
    vault.purge_item(id)?;
    Ok(json!({"ok": true}))
}

pub(crate) fn cmd_restore_version(positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .or_usage("usage: restore-version <id> <at>")?;
    let at = positionals
        .get(std::iter::once(()).count())
        .or_usage("usage: restore-version <id> <at>")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "rotate")?;
    vault.restore_version(id, at)?;
    emit(&json!({"ok": true}))
}

pub(crate) fn cmd_get(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let coordinate = positionals
        .first()
        .or_usage("usage: get <id|role:<role>> [--field <field>]")?;
    let path = vault_path();
    let vault = Vault::open(path.clone())?;
    // `role:<role>` reads the one live item tagged `stado:role:<role>`, the
    // same coordinate acquisition and scoped reads take, so an owner-side
    // reader names what the secret is for instead of an item id.
    let id = &crate::access::acquisition::role::item_for(&vault, coordinate).map_err(|error| {
        match coordinate.strip_prefix("role:") {
            Some(role) if error.is::<crate::access::acquisition::AcquisitionFieldMissing>() => {
                anyhow::anyhow!(
                    "no live item carries stado:role:{role}; tag the item that plays role {role}"
                )
            }
            _ => error,
        }
    })?;
    let item = vault
        .get_item(id)
        .with_context(|| format!("reading item {id} from the vault at {}", path.display()))?;
    let Some(field) = flags.get("field") else {
        return emit(&item);
    };
    if field.is_empty() || field.chars().any(char::is_control) {
        bail!("get --field requires one exact field name, got {field:?}");
    }
    let fields = item.get("fields").and_then(Value::as_object);
    let Some(found) = fields.and_then(|fields| fields.get(field)) else {
        let present: Vec<&str> = fields
            .map(|fields| fields.keys().map(String::as_str).collect())
            .unwrap_or_default();
        bail!(
            "item {id} has no field {field}; its fields are: {}",
            if present.is_empty() {
                "none".to_string()
            } else {
                present.join(", ")
            }
        );
    };
    let value = found.as_str().with_context(|| {
        format!(
            "item {id} field {field} holds {}, not text; read the whole item with `skarbiec get {id}`",
            match found {
                Value::Null => "null",
                Value::Bool(_) => "a boolean",
                Value::Number(_) => "a number",
                Value::Array(_) => "a list",
                Value::Object(_) => "an object",
                Value::String(_) => "text",
            }
        )
    })?;
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
             `skarbiec set` of that item or by `skarbiec upgrade --apply`, so an empty \
             duplicate list over this vault means nothing comparable rather than nothing \
             duplicated"
        ));
    }
    Ok(report)
}
