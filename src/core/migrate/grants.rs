// Turning a legacy grant into declared capabilities: which actions exist,
// which item and field each pattern expands to, and what a glob may match.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::items::canonical_item_id;
use super::patterns::{
    canonical_field, future_contract_field, glob_matches, supported_action,
};

fn expand_capability(
    raw_action: &str,
    target: &str,
    item_fields: &BTreeMap<String, Vec<String>>,
    output: &mut BTreeSet<String>,
) -> Result<()> {
    let action = match raw_action {
        "write" => "stage",
        "delete" => "trash",
        action => action,
    };
    if !supported_action(action) {
        bail!("unsupported legacy grant action: {raw_action}");
    }
    let (item_pattern, requested_field) = target
        .split_once('#')
        .map_or((target, None), |(item, field)| (item, Some(field)));
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
        if action == "read" && requested_field.is_none() && !wildcard {
            output.insert(format!("{action}\u{0}{canonical_pattern}\u{0}"));
            return Ok(());
        }
        if !matches!(action, "stage" | "rotate" | "verify" | "acquire")
            && requested_field.is_none()
            && !wildcard
        {
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
            if field == "context" && action != "read" {
                bail!("context metadata may only be named by read capabilities");
            }
            output.insert(format!("{action}\u{0}{item}\u{0}{field}"));
        } else if matches!(action, "read" | "stage" | "rotate" | "verify" | "acquire") {
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
    let mut migrated = usize::MIN;
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
                let target = capability
                    .get("field")
                    .and_then(Value::as_str)
                    .map_or_else(|| item.to_string(), |field| format!("{item}#{field}"));
                expand_capability(action, &target, item_fields, &mut expanded)?;
            }
        }
        if let Some(scopes) = object.get("scopes").and_then(Value::as_array) {
            for scope in scopes {
                let scope = scope.as_str().context("legacy scope is not a string")?;
                let (action, target) = scope.split_once(':').unwrap_or(("read", scope));
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
                let action = if has_workload_key { "acquire" } else { "read" };
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
        let has_acquire = capabilities
            .iter()
            .any(|capability| capability.get("action").and_then(Value::as_str) == Some("acquire"));
        if has_acquire
            && capabilities.iter().any(|capability| {
                capability.get("action").and_then(Value::as_str) != Some("acquire")
            })
        {
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
            .or_insert_with(|| json!(u64::MAX));
        object
            .entry("workload_public_key".to_string())
            .or_insert(Value::Null);
        migrated = migrated.saturating_add(std::iter::once(()).count());
    }
    Ok(migrated)
}
