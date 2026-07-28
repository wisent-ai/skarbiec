// Long-lived consumer grants. Legacy direct item scopes remain intact;
// acquisition scopes are exact item/field pairs and authorize only issuance of
// a short-lived single-use bearer.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{crypto, vault::Vault, vault_path};

fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

// Anchored glob match with `*` wildcards, no regex dependency and no numeric
// literals: split on '*', walk the literal segments in order.
fn glob_matches(pattern: &str, id: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let starts_wild = pattern.starts_with('*');
    let ends_wild = pattern.ends_with('*');
    let last_index = parts.len().saturating_sub(std::iter::once(()).count());
    let mut pos = id;
    for (index, part) in parts.iter().enumerate() {
        let is_first = index == usize::MIN;
        let is_last = index == last_index;
        if part.is_empty() {
            continue;
        }
        if is_first && is_last && !starts_wild && !ends_wild {
            return pos == *part;
        }
        if is_first && !starts_wild {
            if !pos.starts_with(part) {
                return false;
            }
            pos = &pos[part.len()..];
        } else if is_last && !ends_wild {
            if !pos.ends_with(part) {
                return false;
            }
        } else if let Some(found) = pos.find(part) {
            pos = &pos[found + part.len()..];
        } else {
            return false;
        }
    }
    true
}

fn safe_legacy_atom(value: &str) -> bool {
    !value.trim().is_empty() && value == value.trim() && value != "*"
}

fn scopes_for(vault: &Vault, consumer: &str, presented: &str) -> Result<Option<Vec<String>>> {
    let hash = crypto::sha256_hex(presented)?;
    let entry = match vault.doc().get("tokens").and_then(|t| t.get(consumer)) {
        Some(e) => e,
        None => return Ok(None),
    };
    if entry.get("hash").and_then(Value::as_str) != Some(hash.as_str()) {
        return Ok(None);
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
    Ok(Some(scopes))
}

pub fn token_allows_acquisition(
    vault: &Vault,
    consumer: &str,
    presented: &str,
    item: &str,
    field: &str,
) -> Result<bool> {
    let hash = crypto::sha256_hex(presented)?;
    let Some(entry) = vault
        .doc()
        .get("tokens")
        .and_then(|tokens| tokens.get(consumer))
    else {
        return Ok(false);
    };
    if entry.get("hash").and_then(Value::as_str) != Some(hash.as_str()) {
        return Ok(false);
    }
    Ok(entry
        .get("acquisition_scopes")
        .and_then(Value::as_array)
        .is_some_and(|scopes| {
            scopes.iter().any(|scope| {
                scope.get("item").and_then(Value::as_str) == Some(item)
                    && scope.get("field").and_then(Value::as_str) == Some(field)
            })
        }))
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

/// Used by the runtime resolver: does this consumer + presented secret grant
/// access to `id`?
pub fn token_allows(vault: &Vault, consumer: &str, presented: &str, id: &str) -> Result<bool> {
    if !safe_legacy_atom(consumer) || !safe_legacy_atom(presented) || !safe_legacy_atom(id) {
        return Ok(false);
    }
    match scopes_for(vault, consumer, presented)? {
        Some(scopes) => Ok(scopes.iter().any(|pattern| glob_matches(pattern, id))),
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
            let consumer = positionals
                .first()
                .filter(|value| safe_legacy_atom(value))
                .context(
                    "usage: token-mint <consumer> [--scopes a,b | --acquisition-scopes item#field]",
                )?;
            let scopes: Vec<String> = flags
                .get("scopes")
                .map(|value| value.split(',').map(str::to_string).collect())
                .unwrap_or_default();
            let acquisition_requested = flags.contains_key("acquisition-scopes");
            if acquisition_requested && !scopes.is_empty() {
                anyhow::bail!("direct scopes and acquisition scopes cannot share one grant");
            }
            if acquisition_requested && !exact_component(consumer) {
                anyhow::bail!("acquisition consumer must be one exact name");
            }
            if !acquisition_requested
                && (scopes.is_empty() || scopes.iter().any(|scope| !safe_legacy_atom(scope)))
            {
                anyhow::bail!("legacy scopes must be nonblank and may not be broad '*'");
            }
            let mut vault = load()?;
            let acquisition_scopes = acquisition_scopes(&vault, flags.get("acquisition-scopes"))?;
            let minted = crypto::random_token()?;
            let hash = crypto::sha256_hex(&minted)?;
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
                    }),
                );
            vault.save()?;
            crate::runtime::audit::append(
                "token-mint",
                &json!({
                    "consumer": consumer,
                    "scopes": scopes,
                    "acquisition_scopes": acquisition_scopes,
                }),
            )?;
            Ok(Some(json!({
                "ok": true,
                "consumer": consumer,
                "scopes": scopes,
                "acquisition_scopes": acquisition_scopes,
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
