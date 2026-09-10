// Reading grants: which capabilities a presented credential carries, and the
// questions a caller may ask about one without learning anything else.

use anyhow::Result;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::{crypto, vault::Vault, vault_path};

pub(in crate::access::grant) fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

pub fn presented_hash(presented: &str) -> Result<String> {
    crypto::sha256_hex(presented)
}

pub(in crate::access::grant) fn now_epoch() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub(in crate::access::grant) fn active(entry: &Value) -> bool {
    entry
        .get("expires_at")
        .and_then(Value::as_u64)
        .is_some_and(|expires_at| now_epoch().is_ok_and(|now| now < expires_at))
}

fn capabilities_for_hash<'a>(
    vault: &'a Vault,
    consumer: &str,
    hash: &str,
) -> Option<&'a Vec<Value>> {
    let entry = vault
        .doc()
        .get("tokens")
        .and_then(|tokens| tokens.get(consumer))?;
    if !active(entry) || entry.get("hash").and_then(Value::as_str) != Some(hash) {
        return None;
    }
    entry.get("capabilities").and_then(Value::as_array)
}

fn capabilities_for<'a>(
    vault: &'a Vault,
    consumer: &str,
    presented: &str,
) -> Result<Option<&'a Vec<Value>>> {
    let hash = presented_hash(presented)?;
    Ok(capabilities_for_hash(vault, consumer, &hash))
}

/// Every consumer grant that still authorizes something, with its capabilities.
///
/// Expired entries are left out for the reason `parse_capabilities` already
/// gives about a preserved stale row: a grant that authorizes nothing is
/// already inert, and a diagnosis that reports the vault coordinates of dead
/// grants spends an operator's attention on rows no workload can reach.
/// Liveness is `active`, the same predicate every authorization lookup here
/// applies, so what the diagnosis walks is exactly what a caller could use.
pub(crate) fn live_grants(vault: &Vault) -> Vec<(&str, &Vec<Value>)> {
    vault
        .doc()
        .get("tokens")
        .and_then(Value::as_object)
        .map(|tokens| {
            tokens
                .iter()
                .filter(|(_, entry)| active(entry))
                .filter_map(|(consumer, entry)| {
                    entry
                        .get("capabilities")
                        .and_then(Value::as_array)
                        .map(|capabilities| (consumer.as_str(), capabilities))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[allow(dead_code)]
pub fn token_valid(vault: &Vault, consumer: &str, presented: &str) -> Result<bool> {
    Ok(capabilities_for(vault, consumer, presented)?.is_some())
}

pub fn token_valid_hash(vault: &Vault, consumer: &str, hash: &str) -> bool {
    capabilities_for_hash(vault, consumer, hash).is_some()
}

pub(in crate::access::grant) fn capability_matches(
    capability: &Value,
    action: &str,
    item: &str,
    field: Option<&str>,
) -> bool {
    capability.get("action").and_then(Value::as_str) == Some(action)
        && capability.get("item").and_then(Value::as_str) == Some(item)
        && capability.get("field").and_then(Value::as_str) == field
}

pub fn token_allows_field_action(
    vault: &Vault,
    consumer: &str,
    presented: &str,
    action: &str,
    item: &str,
    field: &str,
) -> Result<bool> {
    Ok(
        capabilities_for(vault, consumer, presented)?.is_some_and(|capabilities| {
            capabilities
                .iter()
                .any(|capability| capability_matches(capability, action, item, Some(field)))
        }),
    )
}

/// What a presented bearer is, asked without being told whose it is.
///
/// Every other lookup here starts from a consumer name and checks the secret
/// against that one entry. A gateway holding an inbound request has the secret
/// and nothing else, and the alternative to answering this question is what
/// Brama does today: keep its own copy of every bearer in the fleet, built at
/// boot, which cannot expire, cannot be revoked, and drifts from this vault the
/// moment anything changes here.
///
/// An unknown bearer and an expired one answer the same way, so the caller
/// learns whether this credential is usable and nothing else about the vault.
pub fn introspect(vault: &Vault, presented: &str) -> Result<Value> {
    let inactive = json!({"active": false});
    if presented.is_empty() {
        return Ok(inactive);
    }
    let hash = presented_hash(presented)?;
    let Some(tokens) = vault.doc().get("tokens").and_then(Value::as_object) else {
        return Ok(inactive);
    };
    for (consumer, entry) in tokens {
        let matches = entry
            .get("hash")
            .and_then(Value::as_str)
            .is_some_and(|stored| stored == hash);
        if !matches {
            continue;
        }
        if !active(entry) {
            return Ok(inactive);
        }
        return Ok(json!({
            "active": true,
            "consumer": consumer,
            "audience": entry.get("audience").cloned().unwrap_or(Value::Null),
            "capabilities": entry.get("capabilities").cloned().unwrap_or(json!([])),
            "expires_at": entry.get("expires_at").cloned().unwrap_or(Value::Null),
        }));
    }
    Ok(inactive)
}

pub fn token_allows_action(
    vault: &Vault,
    consumer: &str,
    presented: &str,
    action: &str,
    item: &str,
) -> Result<bool> {
    Ok(
        capabilities_for(vault, consumer, presented)?.is_some_and(|capabilities| {
            capabilities
                .iter()
                .any(|capability| capability_matches(capability, action, item, None))
        }),
    )
}

pub fn token_allows_any_item_hash(
    vault: &Vault,
    consumer: &str,
    hash: &str,
    action: &str,
    item: &str,
) -> bool {
    capabilities_for_hash(vault, consumer, hash).is_some_and(|capabilities| {
        capabilities.iter().any(|capability| {
            capability.get("action").and_then(Value::as_str) == Some(action)
                && capability.get("item").and_then(Value::as_str) == Some(item)
        })
    })
}

pub fn token_allows_vault_action(
    vault: &Vault,
    consumer: &str,
    presented: &str,
    action: &str,
    resource: &str,
) -> Result<bool> {
    token_allows_action(vault, consumer, presented, action, resource)
}

