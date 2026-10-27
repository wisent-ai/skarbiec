// Turning a legacy grant into declared capabilities: which actions exist,
// which item and field each pattern expands to, and what a glob may match.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::items::canonical_item_id;
use super::patterns::{canonical_field, future_contract_field, glob_matches};
use crate::access::actions::Action;

fn expand_capability(
    raw_action: &str,
    target: &str,
    item_fields: &BTreeMap<String, Vec<String>>,
    output: &mut BTreeSet<String>,
) -> Result<()> {
    // A legacy grant spelled two actions by older names.
    let renamed = match raw_action {
        "write" => "stage",
        "delete" => "trash",
        action => action,
    };
    let Some(kind) = Action::parse(renamed).filter(|kind| kind.legacy()) else {
        bail!("unsupported legacy grant action: {raw_action}");
    };
    let action = kind.as_str();
    let (item_pattern, requested_field) = match target.split_once('#') {
        Some((item, field)) => (item, Some(field)),
        None => (target, None),
    };
    let wildcard = item_pattern.contains('*') || item_pattern.contains('?');
    let canonical_pattern = canonical_item_id(item_pattern);
    let matches: Vec<(&String, &Vec<String>)> = item_fields
        .iter()
        .filter(|(item, _)| glob_matches(&canonical_pattern, item))
        .collect();
    if matches.is_empty() {
        if !wildcard {
            if let Some(field) = future_contract_field(&canonical_pattern, requested_field) {
                output.insert(format!("{action}\u{0}{canonical_pattern}\u{0}{field}"));
                return Ok(());
            }
        }
        if kind.reads_context() && requested_field.is_none() && !wildcard {
            output.insert(format!("{action}\u{0}{canonical_pattern}\u{0}"));
            return Ok(());
        }
        if !kind.needs_field() && requested_field.is_none() && !wildcard {
            output.insert(format!("{action}\u{0}{canonical_pattern}\u{0}"));
            return Ok(());
        }
        // Same reasoning as a grant to a field that no longer exists: a grant
        // naming an item the vault no longer holds has nothing on the other
        // side of it, and aborting here made one stale entry enough to keep
        // every legacy item in the store unreadable permanently. Dropping is
        // faithful and can only narrow access; the line names what went so it
        // can be re-granted deliberately.
        eprintln!("dropping legacy capability {action} {target}: no canonical item of that name");
        return Ok(());
    }
    for (item, fields) in matches {
        if let Some(requested_field) = requested_field {
            // A grant naming a field the item no longer carries cannot be
            // carried forward: there is nothing on the other side of it. It used
            // to abort the whole migration, so one dangling grant left every
            // legacy item in the store unreadable for good -- `key_type` on an
            // ssh item whose canonical fields are the two keys did exactly that
            // here. Dropping the grant is the faithful move and the safe
            // direction: it can only narrow access, never widen it, and the
            // line names what was dropped so the operator can re-grant it.
            let Ok(field) = canonical_field(requested_field, fields) else {
                eprintln!(
                    "dropping legacy capability {action} {item}#{requested_field}: \
                     no canonical field of that name (item carries {})",
                    fields.join(",")
                );
                continue;
            };
            if field == "context" && !kind.reads_context() {
                bail!("context metadata may only be named by read capabilities");
            }
            output.insert(format!("{action}\u{0}{item}\u{0}{field}"));
        } else if kind.per_field() {
            for field in fields {
                output.insert(format!("{action}\u{0}{item}\u{0}{field}"));
            }
        } else {
            output.insert(format!("{action}\u{0}{item}\u{0}"));
        }
    }
    Ok(())
}

pub(super) fn migrate_grants(
    tokens: &mut Map<String, Value>,
    item_fields: &BTreeMap<String, Vec<String>>,
) -> Result<usize> {
    // Every grant the loop reaches is migrated or the migration stops, so the
    // count is the table's own size.
    let migrated = tokens.len();
    for (consumer, entry) in tokens.iter_mut() {
        let object = entry
            .as_object_mut()
            .context("token entry is not an object")?;
        let mut expanded = BTreeSet::new();
        if let Some(capabilities) = object.get("capabilities").and_then(Value::as_array) {
            for capability in capabilities {
                let action = capability
                    .get("action")
                    .and_then(Value::as_str)
                    .context("capability has no action")?;
                let item = capability
                    .get("item")
                    .and_then(Value::as_str)
                    .context("capability has no item")?;
                let target = match capability.get("field").and_then(Value::as_str) {
                    Some(field) => format!("{item}#{field}"),
                    None => item.to_string(),
                };
                expand_capability(action, &target, item_fields, &mut expanded)?;
            }
        }
        if let Some(scopes) = object.get("scopes").and_then(Value::as_array) {
            for scope in scopes {
                let scope = scope.as_str().context("legacy scope is not a string")?;
                // A legacy scope without an action prefix is a read scope: the
                // pre-v2 grant format wrote only read scopes bare.
                let (action, target) = match scope.split_once(':') {
                    Some(pair) => pair,
                    None => (Action::Read.as_str(), scope),
                };
                expand_capability(action, target, item_fields, &mut expanded)?;
            }
        }
        let has_workload_key = object
            .get("workload_public_key")
            .and_then(Value::as_str)
            .is_some();
        if let Some(scopes) = object.get("acquisition_scopes").and_then(Value::as_array) {
            for scope in scopes {
                let item = scope
                    .get("item")
                    .and_then(Value::as_str)
                    .context("legacy acquisition scope has no item")?;
                let field = scope
                    .get("field")
                    .and_then(Value::as_str)
                    .context("legacy acquisition scope has no field")?;
                let action = match has_workload_key {
                    true => Action::Acquire.as_str(),
                    false => Action::Read.as_str(),
                };
                expand_capability(
                    action,
                    &format!("{item}#{field}"),
                    item_fields,
                    &mut expanded,
                )?;
            }
        }
        let capabilities: Vec<Value> = expanded
            .into_iter()
            .filter_map(|encoded| {
                let mut parts = encoded.split('\0');
                let action = parts.next()?;
                let item = parts.next()?;
                let field = parts.next().filter(|field| !field.is_empty());
                Some(json!({"action": action, "item": item, "field": field}))
            })
            .collect();
        let is_acquire = |capability: &Value| Action::of(capability) == Some(Action::Acquire);
        let has_acquire = capabilities.iter().any(is_acquire);
        if has_acquire && !capabilities.iter().all(is_acquire) {
            bail!("{consumer} mixes acquisition and direct capabilities");
        }
        if has_acquire {
            object.insert("hash".to_string(), Value::Null);
        } else {
            object.insert("workload_public_key".to_string(), Value::Null);
        }
        object.remove("scopes");
        object.remove("acquisition_scopes");
        object.insert("capabilities".to_string(), Value::Array(capabilities));
        object
            .entry("audience".to_string())
            .or_insert_with(|| json!(consumer));
        object
            .entry("expires_at".to_string())
            .or_insert_with(|| json!(crate::access::grant::UNTIL_REVOKED));
        object
            .entry("workload_public_key".to_string())
            .or_insert(Value::Null);
    }
    Ok(migrated)
}
