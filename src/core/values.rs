// Value operations on vault items: get, set, set-json.
//
// These are the same operations the command line offers, delegating to the
// same Vault API so the operator console and the local vault cannot drift.

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
                .context("usage: credential get <id> [--field <field>]")?;
            let item = Vault::open(vault_path())?.get_item(id)?;
            if let Some(field) = flags.get("field") {
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
                Ok(Some(json!({"value": value})))
            } else {
                // Return the full item as a JSON string wrapped in the value field
                let item_json = serde_json::to_string(&item)?;
                Ok(Some(json!({"value": item_json})))
            }
        }
        ("credential", "set") => {
            let id = positionals
                .get(1)
                .context("usage: credential set <id> [--type <canonical-kind>] k=v ...")?;
            let item_kind = flags.get("type").map(String::as_str).unwrap_or("login");
            let mut vault = Vault::open(vault_path())?;
            ensure_owner_set_allowed(&vault, id)?;
            let fields: Vec<String> = positionals
                .iter()
                .skip(2)
                .cloned()
                .collect();
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
                .context("usage: credential set-json <id> [--type <canonical-kind>]")?;
            let mut vault = Vault::open(vault_path())?;
            ensure_owner_set_allowed(&vault, id)?;

            // For operator route, the JSON payload comes from the request body
            let payload: Value = if let Some(payload_value) = flags.get("__payload__") {
                serde_json::from_str(payload_value)
                    .context("payload must be valid JSON")?
            } else {
                bail!("set-json payload required")
            };

            let payload_kind = payload
                .get("kind")
                .and_then(Value::as_str)
                .context("set-json payload requires kind")?;
            let item_kind = flags
                .get("type")
                .map(String::as_str)
                .unwrap_or(payload_kind);
            schema::validate_payload(&payload, item_kind)?;
            let recipients = requested_or_existing(flags, &vault, id, "recipients");
            let tags = requested_or_existing(flags, &vault, id, "tags");
            ensure_no_reserved_tags(&tags)?;
            let writer = vault.owner_uid().to_string();
            vault.set_item_written_by(id, item_kind, &payload, &recipients, &tags, &writer)?;
            Ok(Some(json!({"ok": true, "id": id, "kind": item_kind})))
        }
        _ => Ok(None),
    }
}

/// Check whether the operator is allowed to write this item.
fn ensure_owner_set_allowed(vault: &Vault, id: &str) -> Result<()> {
    let item = vault.get_item(id).ok();
    match item {
        None => Ok(()), // New item, always allowed
        Some(item) => {
            // Existing item: only the owner can change it
            if let Some(writer) = item.get("writer").and_then(Value::as_str) {
                if writer != vault.owner_uid() {
                    bail!(
                        "item {} is owned by {}, only the owner can modify it",
                        id,
                        writer
                    );
                }
            }
            Ok(())
        }
    }
}

/// Get the value for a field, using requested if present, otherwise existing.
fn requested_or_existing(
    flags: &HashMap<String, String>,
    vault: &Vault,
    id: &str,
    field: &str,
) -> Vec<String> {
    if let Some(value) = flags.get(field) {
        return value
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    match vault.get_item(id) {
        Ok(item) => {
            item.get(field)
                .and_then(Value::as_array)
                .map(|array| {
                    array
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        }
        Err(_) => Vec::new(),
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
