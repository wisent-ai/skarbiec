// Parsing the capabilities a grant declares, the catalog an acquisition may
// be issued from, and the redemption contract a workload-bound grant answers
// with.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::validation::{
    allowed_action, effective_uid, exact_component, exact_resource, exact_route,
};
use crate::access::grant::lookup::{active, capability_matches};
use crate::core::{schema, vault::Vault};

pub(in crate::access::grant) fn parse_capabilities(
    vault: &Vault,
    raw: &str,
    preserved_capabilities: &[Value],
) -> Result<Vec<Value>> {
    if raw.trim().is_empty() {
        bail!("grant issue requires --capabilities action:item[#field]");
    }
    let mut capabilities = Vec::new();
    for encoded in raw.split(',') {
        let (action, target) = encoded
            .split_once(':')
            .context("capabilities use action:item[#field]")?;
        if !allowed_action(action) {
            bail!("unsupported capability action: {action}");
        }
        let (item, field) = match target.split_once('#') {
            Some((item, field)) => (item, Some(field)),
            None => (target, None),
        };
        // A `call` field names a route inside a service, and routes have
        // separators: `wisent-backend/chat/primary` is one name, not a pattern.
        // Everywhere else a field is a single component of an item.
        let field_ok = match field {
            None => true,
            Some(field) if action == "call" => exact_route(field),
            Some(field) => exact_component(field),
        };
        if !exact_resource(item) || !field_ok {
            bail!("capabilities require exact resource and field names without globs");
        }
        if matches!(action, "acquire" | "stage" | "rotate" | "verify") && field.is_none() {
            bail!("{action} capability requires one exact field");
        }
        if matches!(action, "lifecycle" | "reseal") && field.is_some() {
            bail!("{action} capability is item-scoped and must not name a field");
        }
        let capability = json!({"action": action, "item": item, "field": field});
        if capabilities.contains(&capability) {
            bail!("duplicate capability: {encoded}");
        }
        // Re-minting an existing bearer may preserve an old capability whose
        // item was later trashed. That capability is already inert and is not
        // being granted here. Re-validating it would make one stale row block
        // every unrelated field addition, while dropping it would silently
        // narrow the consumer. Validate only capabilities this mint introduces.
        let preserved = preserved_capabilities.contains(&capability);

        // A `call` capability names a service and a route inside it, not a vault
        // item and one of its fields, so there is nothing here to exist yet.
        // Checking would tie the right to reach a service to that service
        // happening to keep a secret.
        if action == "call" {
            capabilities.push(capability);
            continue;
        }
        if !preserved {
            if let Some(field) = field {
                if field == "context" && action != "read" {
                    bail!("context is metadata and may only be named by read capabilities");
                }
                let item_exists = vault
                    .doc()
                    .get("items")
                    .and_then(Value::as_object)
                    .is_some_and(|items| items.contains_key(item));
                if item_exists {
                    let payload = vault.get_item(item)?;
                    if schema::field(&payload, field).is_err()
                        && !(matches!(action, "stage" | "acquire")
                            && schema::allows_field(&payload, field))
                    {
                        bail!("capability names a missing field: {item}#{field}");
                    }
                } else if !matches!(action, "stage" | "acquire") {
                    bail!("capability names a missing item: {item}");
                }
            } else if matches!(
                action,
                "share" | "trash" | "purge" | "admin" | "lifecycle" | "reseal"
            ) {
                vault
                    .doc()
                    .get("items")
                    .and_then(|items| items.get(item))
                    .with_context(|| format!("capability names a missing item: {item}"))?;
            }
        }
        capabilities.push(capability);
    }
    Ok(capabilities)
}

pub(in crate::access::grant) fn read_acquisition_catalog(
    path: &Path,
) -> Result<Vec<(String, String, String)>> {
    if !path.is_absolute() {
        bail!("acquisition catalog path must be absolute");
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.uid() != effective_uid()? {
        bail!("acquisition catalog must be an owner-controlled regular file");
    }
    let mut rows = Vec::new();
    for line in fs::read_to_string(path)?.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let columns: Vec<&str> = line.split('|').collect();
        if columns.len() != ["consumer", "item", "field"].len()
            || !columns.iter().all(|value| exact_component(value))
        {
            bail!("invalid acquisition catalog row: {line}");
        }
        let row = (
            columns[usize::MIN].to_string(),
            columns[std::iter::once(()).count()].to_string(),
            columns[std::iter::once(())
                .count()
                .saturating_add(std::iter::once(()).count())]
            .to_string(),
        );
        if rows.iter().any(|existing| existing == &row) {
            bail!("duplicate acquisition catalog row: {line}");
        }
        if rows.iter().any(|(consumer, _, _)| consumer == &row.0) {
            bail!("each acquisition catalog consumer must name one exact field");
        }
        rows.push(row);
    }
    if rows.is_empty() {
        bail!("acquisition catalog cannot be empty");
    }
    Ok(rows)
}

pub fn acquisition_workload_public_key(
    vault: &Vault,
    consumer: &str,
    item: &str,
    field: &str,
) -> Option<String> {
    let entry = vault
        .doc()
        .get("tokens")
        .and_then(|tokens| tokens.get(consumer))?;
    if !active(entry) {
        return None;
    }
    let allowed = entry
        .get("capabilities")
        .and_then(Value::as_array)
        .is_some_and(|capabilities| {
            capabilities
                .iter()
                .any(|capability| capability_matches(capability, "acquire", item, Some(field)))
        });
    if !allowed {
        return None;
    }
    entry
        .get("workload_public_key")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Every workload-bound coordinate a grant declares, and how each is spent.
///
/// One row per `acquire` capability, because a grant may declare several and a
/// caller has to be told the exact item and field its proof is signed over.
pub(in crate::access::grant) fn redemption_contract(
    consumer: &str,
    capabilities: &[Value],
) -> Vec<Value> {
    capabilities
        .iter()
        .filter(|capability| {
            capability.get("action").and_then(Value::as_str) == Some("acquire")
        })
        .filter_map(|capability| {
            let item = capability.get("item").and_then(Value::as_str)?;
            let field = capability.get("field").and_then(Value::as_str)?;
            Some(json!({
                "item": item,
                "field": field,
                "how": format!(
                    "sign an acquisition proof, then run: skarbiec acquisition-request {consumer} {item} {field} --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX; consume its token once with acquisition-read"
                ),
            }))
        })
        .collect()
}
