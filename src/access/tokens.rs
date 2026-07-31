// Long-lived consumer grants. Direct action scopes retain the existing item
// behavior; acquisition scopes are exact item/field pairs and authorize only
// issuance of a short-lived single-use bearer.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use crate::core::{crypto, glob_matches, vault::Vault, vault_path};

fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

/// Hash one presented bearer once per request. `crypto::sha256_hex` shells
/// out to `shasum`, so handlers checking many items in one loop must hoist
/// this call and use the `_hash` variants below instead of the per-check
/// ones — otherwise each item costs a subprocess spawn.
pub fn presented_hash(presented: &str) -> Result<String> {
    crypto::sha256_hex(presented)
}

fn scopes_for_hash(vault: &Vault, consumer: &str, hash: &str) -> Option<Vec<String>> {
    let entry = vault.doc().get("tokens").and_then(|t| t.get(consumer))?;
    if entry.get("hash").and_then(Value::as_str) != Some(hash) {
        return None;
    }
    let scopes = entry
        .get("scopes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Some(scopes)
}

fn scopes_for(vault: &Vault, consumer: &str, presented: &str) -> Result<Option<Vec<String>>> {
    let hash = presented_hash(presented)?;
    Ok(scopes_for_hash(vault, consumer, &hash))
}

/// Authenticate a consumer grant without authorizing any particular item.
/// Single-check call sites use this; per-item loops use [`token_valid_hash`].
#[allow(dead_code)]
pub fn token_valid(vault: &Vault, consumer: &str, presented: &str) -> Result<bool> {
    Ok(scopes_for(vault, consumer, presented)?.is_some())
}

/// [`token_valid`] with a precomputed bearer hash (see [`presented_hash`]).
pub fn token_valid_hash(vault: &Vault, consumer: &str, hash: &str) -> bool {
    scopes_for_hash(vault, consumer, hash).is_some()
}

fn effective_uid() -> Result<u32> {
    let output = Command::new("id").arg("-u").output()?;
    if !output.status.success() {
        anyhow::bail!("could not determine effective uid");
    }
    String::from_utf8(output.stdout)?
        .trim()
        .parse()
        .context("parse effective uid")
}

fn read_workload_public_key(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    let unsafe_bits = u32::from_str_radix("077", "8".parse()?)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()?
        || metadata.mode() & unsafe_bits != u32::MIN
    {
        anyhow::bail!("workload public key must be an owner-controlled regular file");
    }
    let key = fs::read_to_string(path)?;
    let maximum: usize = "8192".parse()?;
    if key.is_empty()
        || key.len() > maximum
        || !key.contains("-----BEGIN PUBLIC KEY-----")
        || !key.contains("-----END PUBLIC KEY-----")
    {
        anyhow::bail!("workload public key must be a bounded PEM public key");
    }
    let output = Command::new("openssl")
        .args(["pkey", "-pubin", "-in"])
        .arg(path)
        .args(["-text_pub", "-noout"])
        .output()
        .context("validate workload public key with openssl")?;
    let description = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || !description.to_ascii_uppercase().contains("ED25519") {
        anyhow::bail!("workload public key must be a valid Ed25519 public key");
    }
    Ok(key)
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
    let allowed = entry
        .get("acquisition_scopes")
        .and_then(Value::as_array)
        .is_some_and(|scopes| {
            scopes.iter().any(|scope| {
                scope.get("item").and_then(Value::as_str) == Some(item)
                    && scope.get("field").and_then(Value::as_str) == Some(field)
            })
        });
    if !allowed {
        return None;
    }
    entry
        .get("workload_public_key")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn exact_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn acquisition_scopes(vault: &Vault, raw: Option<&String>) -> Result<Vec<Value>> {
    let Some(encoded) = raw else {
        return Ok(Vec::new());
    };
    if encoded.contains(',') {
        anyhow::bail!("an acquisition bootstrap grant must name exactly one field");
    }
    let (item, field) = encoded
        .split_once('#')
        .context("acquisition scopes use one exact item#field entry")?;
    if !exact_component(item) || !exact_component(field) {
        anyhow::bail!("acquisition scopes prohibit wildcards, globs, and empty names");
    }
    let secret = vault.get_item(item)?;
    if !secret
        .as_object()
        .is_some_and(|object| object.contains_key(field))
    {
        anyhow::bail!("acquisition scope names a missing item field");
    }
    Ok(vec![json!({"item": item, "field": field})])
}
/// Match one already-resolved scope set against an action on one item.
///
/// Action-aware scopes use `read:<glob>`, `write:<glob>`, or `delete:<glob>`.
/// Legacy bare globs remain read-only so existing resolver grants do not gain
/// mutation rights when the HTTP item API is enabled.
fn scopes_allow(scopes: &[String], action: &str, id: &str) -> bool {
    scopes.iter().any(|scope| {
        if let Some((scope_action, pattern)) = scope.split_once(':') {
            scope_action == action && glob_matches(pattern, id)
        } else {
            action == "read" && glob_matches(scope, id)
        }
    })
}

/// Check whether a consumer grant authorizes an action on one item.
pub fn token_allows_action(
    vault: &Vault,
    consumer: &str,
    presented: &str,
    action: &str,
    id: &str,
) -> Result<bool> {
    match scopes_for(vault, consumer, presented)? {
        Some(scopes) => Ok(scopes_allow(&scopes, action, id)),
        None => Ok(false),
    }
}

/// [`token_allows_action`] with a precomputed bearer hash: the per-item loop
/// form that costs no subprocess per item (see [`presented_hash`]).
pub fn token_allows_action_hash(
    vault: &Vault,
    consumer: &str,
    hash: &str,
    action: &str,
    id: &str,
) -> bool {
    match scopes_for_hash(vault, consumer, hash) {
        Some(scopes) => scopes_allow(&scopes, action, id),
        None => false,
    }
}

/// Backward-compatible read authorization used by the runtime resolvers.
pub fn token_allows(vault: &Vault, consumer: &str, presented: &str, id: &str) -> Result<bool> {
    token_allows_action(vault, consumer, presented, "read", id)
}

/// Check whether a consumer grant authorizes a vault-wide action that names
/// no item id: `sync:pull` authorizes serving the whole ciphertext document,
/// and a bare `donate` (or `donate:<glob>`) authorizes an inbound p2p item
/// write. These are checked only by the vault-level endpoints, so they can
/// never widen an item read; a bare glob stays read-only for items.
pub fn token_allows_vault_action(
    vault: &Vault,
    consumer: &str,
    presented: &str,
    action: &str,
    capability: &str,
) -> Result<bool> {
    match scopes_for(vault, consumer, presented)? {
        Some(scopes) => Ok(scopes.iter().any(|scope| match scope.split_once(':') {
            Some((scope_action, pattern)) => {
                scope_action == action && glob_matches(pattern, capability)
            }
            None => capability.is_empty() && scope == action,
        })),
        None => Ok(false),
    }
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "token-mint" => {
            let consumer = positionals.first().context(
                "usage: token-mint <consumer> [--scopes a,b | --acquisition-scopes item#field --workload-public-key-file PATH]",
            )?;
            let scopes: Vec<String> = flags
                .get("scopes")
                .map(|value| value.split(',').map(str::to_string).collect())
                .unwrap_or_default();
            if !scopes.is_empty() && flags.contains_key("acquisition-scopes") {
                anyhow::bail!("direct scopes and acquisition scopes cannot share one grant");
            }
            if flags.contains_key("acquisition-scopes") && !exact_component(consumer) {
                anyhow::bail!("acquisition consumer must be one exact name");
            }
            let mut vault = load()?;
            let acquisition_scopes = acquisition_scopes(&vault, flags.get("acquisition-scopes"))?;
            let workload_public_key = match flags.get("workload-public-key-file") {
                Some(path) => Some(read_workload_public_key(Path::new(path))?),
                None => None,
            };
            if !acquisition_scopes.is_empty() && workload_public_key.is_none() {
                anyhow::bail!(
                    "acquisition grants require --workload-public-key-file with an owner-controlled PEM public key"
                );
            }
            if acquisition_scopes.is_empty() && workload_public_key.is_some() {
                anyhow::bail!("workload public keys are valid only for acquisition grants");
            }
            let minted = if acquisition_scopes.is_empty() {
                Some(crypto::random_token()?)
            } else {
                None
            };
            let hash = match minted.as_deref() {
                Some(token) => json!(crypto::sha256_hex(token)?),
                None => Value::Null,
            };
            vault
                .doc_mut()
                .get_mut("tokens")
                .and_then(Value::as_object_mut)
                .context("tokens section")?
                .insert(
                    consumer.clone(),
                    json!({
                        "hash": hash,
                        "scopes": scopes,
                        "acquisition_scopes": acquisition_scopes,
                        "workload_public_key": workload_public_key,
                    }),
                );
            vault.save()?;
            crate::runtime::audit::append(
                "token-mint",
                &json!({
                    "consumer": consumer,
                    "scopes": scopes,
                    "acquisition_scopes": acquisition_scopes,
                    "workload_bound": workload_public_key.is_some(),
                }),
            )?;
            Ok(Some(json!({
                "ok": true,
                "consumer": consumer,
                "scopes": scopes,
                "acquisition_scopes": acquisition_scopes,
                "workload_bound": workload_public_key.is_some(),
                "token": minted,
            })))
        }
        "token-revoke" => {
            let consumer = positionals
                .first()
                .context("usage: token-revoke <consumer>")?;
            let mut vault = load()?;
            vault
                .doc_mut()
                .get_mut("tokens")
                .and_then(Value::as_object_mut)
                .context("tokens section")?
                .remove(consumer);
            vault.save()?;
            crate::runtime::audit::append("token-revoke", &json!({"consumer": consumer}))?;
            Ok(Some(json!({"ok": true, "consumer": consumer})))
        }
        "token-verify" => {
            let mut args = positionals.iter();
            let consumer = args
                .next()
                .context("usage: token-verify <consumer> <item-id> --token T")?;
            let id = args
                .next()
                .context("usage: token-verify <consumer> <item-id> --token T")?;
            let presented = flags.get("token").context("--token required")?;
            let vault = load()?;
            let allowed = token_allows(&vault, consumer, presented, id)?;
            Ok(Some(
                json!({"consumer": consumer, "item": id, "allowed": allowed}),
            ))
        }
        "tokens" => {
            let vault = load()?;
            let listing: Vec<Value> = vault
                .doc()
                .get("tokens")
                .and_then(Value::as_object)
                .map(|tokens| {
                    tokens
                        .iter()
                        .map(|(consumer, entry)| {
                            json!({
                                "consumer": consumer,
                                "scopes": entry.get("scopes"),
                                "acquisition_scopes": entry.get("acquisition_scopes"),
                                "workload_bound": entry
                                    .get("workload_public_key")
                                    .and_then(Value::as_str)
                                    .is_some(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(Some(json!(listing)))
        }
        _ => Ok(None),
    }
}
