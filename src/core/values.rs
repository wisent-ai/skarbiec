// Value operations on vault items: get, set, set-json.
//
// These are the same operations the command line offers, delegating to the
// same Vault API so the operator console and the local vault cannot drift.

use crate::cli::args::OrUsage;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{items, schema, vault::Vault, vault_path};

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    let subcommand = positionals.first().map(String::as_str).unwrap_or("help");
    match (command, subcommand) {
        ("credential", "get") => {
            let id = positionals
                .get(1)
                .or_usage("usage: credential get <id> [--field <field>]")?;
            let value = crate::cli::reads::get_value(flags, std::slice::from_ref(id))?;
            if flags.contains_key("field") {
                Ok(Some(json!({"value": value})))
            } else {
                // Return the full item as a JSON string wrapped in the value field
                let item_json = serde_json::to_string(&value)?;
                Ok(Some(json!({"value": item_json})))
            }
        }
        ("credential", "set") => {
            let id = positionals
                .get(1)
                .or_usage("usage: credential set <id> [--type <canonical-kind>] k=v ...")?;
            let item_kind = flags.get("type").map(String::as_str).unwrap_or("login");
            let mut vault = Vault::open(vault_path())?;
            ensure_owner_set_allowed(&vault, id)?;
            let fields: Vec<String> = positionals.iter().skip(2).cloned().collect();
            let payload = items::build_item(item_kind, &fields)?;
            let recipients = requested_or_existing(flags, &vault, id, "recipients");
            let tags = requested_or_existing(flags, &vault, id, "tags");
            ensure_no_reserved_tags(&tags)?;
            let writer = vault.owner_uid().to_string();
            vault.set_item_written_by(id, item_kind, &payload, &recipients, &tags, &writer)?;
            Ok(Some(json!({"ok": true, "id": id, "kind": item_kind})))
        }
        ("credential", "set-json") => {
            let id = positionals
                .get(1)
                .or_usage("usage: credential set-json <id> [--type <canonical-kind>]")?;
            let encoded = flags
                .get("__payload__")
                .context("set-json payload required")?;
            Ok(Some(crate::cli::items::set_json_value(flags, id, encoded)?))
        }
        _ => Ok(None),
    }
}

/// Check whether the operator may write this item, exactly as the CLI's set
/// does: never on a replica, and on an existing item only through the owner's
/// mutation check.
///
/// This read a `writer` field out of `get_item`'s decrypted payload, which
/// never carries one, and took any failure to decrypt as a new item; the
/// console's set therefore wrote over items owned by someone else, managed
/// items, and items on a replica that the next pull would undo.
fn ensure_owner_set_allowed(vault: &Vault, id: &str) -> Result<()> {
    crate::cli::items::ensure_not_replica(vault, "set")?;
    let item_exists = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .is_some_and(|items| items.contains_key(id));
    if !item_exists {
        return Ok(());
    }
    crate::cli::items::ensure_owner_mutation_allowed(vault, id, "rotate")
}

/// One metadata list: what the caller asked for, or what the item's envelope
/// already carries when the caller said nothing about it.
///
/// This read `get_item`, which answers the decrypted payload, where neither
/// list lives; every `credential set` from the console without `--tags` and
/// `--recipients` therefore wrote empty lists over the item's own, stripping
/// the tags its consumers enumerate it by and narrowing its recipients to the
/// owner, and a vault that could not decrypt the item did the same.
fn requested_or_existing(
    flags: &HashMap<String, String>,
    vault: &Vault,
    id: &str,
    key: &str,
) -> Vec<String> {
    if let Some(value) = flags.get(key) {
        return value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_string)
            .collect();
    }
    match vault
        .doc()
        .get("items")
        .and_then(|items| items.get(id))
        .and_then(|item| item.get(key))
        .and_then(Value::as_array)
    {
        Some(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        None => Vec::new(),
    }
}

/// Ensure the tag list has no reserved tags.
fn ensure_no_reserved_tags(tags: &[String]) -> Result<()> {
    for tag in tags {
        if tag.starts_with("lifecycle:") {
            bail!("tag {tag} is reserved");
        }
    }
    Ok(())
}
