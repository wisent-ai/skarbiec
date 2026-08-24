// Structured, exact consumer capabilities. Long-lived grants authenticate a
// consumer; workload-bound `acquire` capabilities may only mint a short-lived,
// field-bound, single-use bearer through the acquisition module.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::{crypto, schema, vault::Vault, vault_path};

fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

pub fn presented_hash(presented: &str) -> Result<String> {
    crypto::sha256_hex(presented)
}

fn now_epoch() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn active(entry: &Value) -> bool {
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

#[allow(dead_code)]
pub fn token_valid(vault: &Vault, consumer: &str, presented: &str) -> Result<bool> {
    Ok(capabilities_for(vault, consumer, presented)?.is_some())
}

pub fn token_valid_hash(vault: &Vault, consumer: &str, hash: &str) -> bool {
    capabilities_for_hash(vault, consumer, hash).is_some()
}

fn capability_matches(capability: &Value, action: &str, item: &str, field: Option<&str>) -> bool {
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

fn effective_uid() -> Result<u32> {
    let output = Command::new("id").arg("-u").output()?;
    if !output.status.success() {
        bail!("could not determine effective uid");
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
        bail!("workload public key must be an owner-controlled regular file");
    }
    let key = fs::read_to_string(path)?;
    let maximum: usize = "8192".parse()?;
    if key.is_empty()
        || key.len() > maximum
        || !key.contains("-----BEGIN PUBLIC KEY-----")
        || !key.contains("-----END PUBLIC KEY-----")
    {
        bail!("workload public key must be a bounded PEM public key");
    }
    let output = Command::new("openssl")
        .args(["pkey", "-pubin", "-in"])
        .arg(path)
        .args(["-text_pub", "-noout"])
        .output()
        .context("validate workload public key with openssl")?;
    let description = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || !description.to_ascii_uppercase().contains("ED25519") {
        bail!("workload public key must be a valid Ed25519 public key");
    }
    Ok(key)
}

fn read_fixed_token(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    let unsafe_bits = u32::from_str_radix("077", "8".parse()?)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()?
        || metadata.mode() & unsafe_bits != u32::MIN
    {
        bail!("token file must be an owner-controlled regular file");
    }
    let contents = fs::read_to_string(path)?;
    let token = contents.trim_end_matches(['\r', '\n']);
    if token.is_empty() || token.len() > "4096".parse()? || token.chars().any(char::is_whitespace) {
        bail!("token file must contain one bounded non-whitespace token");
    }
    Ok(token.to_string())
}

fn exact_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn exact_resource(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

fn allowed_action(action: &str) -> bool {
    matches!(
        action,
        "acquire"
            | "read"
            | "stage"
            | "rotate"
            | "verify"
            | "revoke"
            | "share"
            | "trash"
            | "purge"
            | "admin"
            | "sync"
            | "enroll"
            | "donate"
            // Credential lifecycle: drive operations on one exact item, and
            // reseal its directory contract. Neither reads a value.
            | "lifecycle"
            | "reseal"
            // Ask what an inbound bearer is. Held by a gateway that has to
            // decide whether to serve a request, so that deciding does not
            // require keeping a copy of every credential in the fleet. Reads no
            // value: the answer is an identity and its capabilities.
            | "introspect"
            // Be called. The right to reach a service, and with `#field` the
            // exact route within it, so a client's reach is a grant here rather
            // than a list compiled into the service it calls.
            | "call"
    )
}

/// A route within a service: components joined by `/`, each one exact.
///
/// Separators are allowed because a route has them; nothing else is. No empty
/// component, so neither a leading nor a trailing slash nor `//`, and no `..`,
/// which is how a path pattern would otherwise reach outside what was granted.
fn exact_route(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= "128".parse().unwrap_or(usize::MAX)
        && value.split('/').all(exact_component)
        && !value.split('/').any(|component| component == "..")
}

fn parse_capabilities(vault: &Vault, raw: &str) -> Result<Vec<Value>> {
    if raw.trim().is_empty() {
        bail!("token-mint requires --capabilities action:item[#field]");
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
        // A `call` capability names a service and a route inside it, not a vault
        // item and one of its fields, so there is nothing here to exist yet.
        // Checking would tie the right to reach a service to that service
        // happening to keep a secret.
        if action == "call" {
            capabilities.push(json!({"action": action, "item": item, "field": field}));
            continue;
        }
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
        let capability = json!({"action": action, "item": item, "field": field});
        if capabilities.contains(&capability) {
            bail!("duplicate capability: {encoded}");
        }
        capabilities.push(capability);
    }
    Ok(capabilities)
}

fn read_acquisition_catalog(path: &Path) -> Result<Vec<(String, String, String)>> {
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

fn mint_once(
    consumer: &str,
    flags: &std::collections::HashMap<String, String>,
    attempt: u32,
) -> anyhow::Result<Value> {
    let _ = attempt;

    let mut vault = load()?;
    let capabilities = parse_capabilities(
        &vault,
        flags
            .get("capabilities")
            .context("--capabilities is required")?,
    )?;
    if let Some(existing) = vault
        .doc()
        .get("tokens")
        .and_then(Value::as_object)
        .and_then(|tokens| tokens.get(consumer))
    {
        let existing_capabilities = existing
            .get("capabilities")
            .and_then(Value::as_array)
            .context("existing grant is not v2; run migrate-v2 first")?;
        let same_capabilities = existing_capabilities.len() == capabilities.len()
            && existing_capabilities
                .iter()
                .all(|capability| capabilities.contains(capability));
        let replace_capabilities = flags
            .get("replace-capabilities")
            .is_some_and(|value| value == "true");
        if !same_capabilities && !replace_capabilities {
            bail!(
                "token-mint refuses to change existing capabilities without --replace-capabilities"
            );
        }
    }
    let has_acquire = capabilities
        .iter()
        .any(|capability| capability.get("action").and_then(Value::as_str) == Some("acquire"));
    if has_acquire
        && capabilities
            .iter()
            .any(|capability| capability.get("action").and_then(Value::as_str) != Some("acquire"))
    {
        bail!("acquire capabilities cannot share a grant with direct capabilities");
    }
    // Driving a credential lifecycle never authorizes reading the
    // value it rotates, so the two never share one bearer.
    let action_of = |capability: &Value| {
        capability
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    if capabilities
        .iter()
        .any(|capability| action_of(capability) == "lifecycle")
        && capabilities
            .iter()
            .any(|capability| action_of(capability) == "read")
    {
        bail!("lifecycle capabilities cannot share a grant with read capabilities");
    }
    let workload_public_key = match flags.get("workload-public-key-file") {
        Some(path) => Some(read_workload_public_key(Path::new(path))?),
        None if has_acquire => {
            bail!("acquire capabilities require --workload-public-key-file")
        }
        None => None,
    };
    if !has_acquire && workload_public_key.is_some() {
        bail!("workload public keys are valid only for acquire capabilities");
    }
    let ttl_seconds: u64 = flags
        .get("ttl-seconds")
        .map(String::as_str)
        .unwrap_or("2592000")
        .parse()
        .context("--ttl-seconds must be an integer")?;
    if ttl_seconds == u64::MIN {
        bail!("--ttl-seconds must be positive");
    }
    let expires_at = now_epoch()?
        .checked_add(ttl_seconds)
        .context("grant expiry overflow")?;
    let supplied_token = flags
        .get("token-file")
        .map(|path| read_fixed_token(Path::new(path)))
        .transpose()?;
    if has_acquire && supplied_token.is_some() {
        bail!("acquire capabilities cannot use --token-file");
    }
    let generated_token = if has_acquire || supplied_token.is_some() {
        None
    } else {
        Some(crypto::random_token()?)
    };
    let stored_token = supplied_token.as_deref().or(generated_token.as_deref());
    let hash = match stored_token {
        Some(token) => json!(crypto::sha256_hex(token)?),
        None => Value::Null,
    };
    let audience = flags
        .get("audience")
        .map(String::as_str)
        .unwrap_or(consumer);
    vault
        .doc_mut()
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .context("tokens section")?
        .insert(
            consumer.to_string(),
            json!({
                "hash": hash,
                "capabilities": capabilities,
                "workload_public_key": workload_public_key,
                "audience": audience,
                "expires_at": expires_at,
            }),
        );
    vault.save()?;
    crate::runtime::audit::append(
        "token-mint",
        &json!({
            "consumer": consumer,
            "capabilities": capabilities,
            "workload_bound": workload_public_key.is_some(),
            "audience": audience,
            "expires_at": expires_at,
        }),
    )?;
    Ok(json!({
        "ok": true,
        "consumer": consumer,
        "capabilities": capabilities,
        "workload_bound": workload_public_key.is_some(),
        "audience": audience,
        "expires_at": expires_at,
        "token": generated_token,
    }))
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "token-register-acquisitions" => {
            let catalog = positionals.first().context(
                "usage: token-register-acquisitions <absolute-catalog> --workload-public-key-file PATH [--ttl-seconds N] [--replace-capabilities]",
            )?;
            let allowed_flags = [
                "workload-public-key-file",
                "ttl-seconds",
                "replace-capabilities",
            ];
            if flags
                .keys()
                .any(|flag| !allowed_flags.contains(&flag.as_str()))
            {
                bail!("unsupported token-register-acquisitions flag");
            }
            let public_key_path = flags
                .get("workload-public-key-file")
                .context("--workload-public-key-file is required")?;
            let workload_public_key = read_workload_public_key(Path::new(public_key_path))?;
            let ttl_seconds: u64 = flags
                .get("ttl-seconds")
                .map(String::as_str)
                .unwrap_or("2592000")
                .parse()
                .context("--ttl-seconds must be an integer")?;
            if ttl_seconds == u64::MIN {
                bail!("--ttl-seconds must be positive");
            }
            let expires_at = now_epoch()?
                .checked_add(ttl_seconds)
                .context("grant expiry overflow")?;
            let replace = flags
                .get("replace-capabilities")
                .is_some_and(|value| value == "true");
            let rows = read_acquisition_catalog(Path::new(catalog))?;
            let mut vault = load()?;
            let mut registrations = Vec::new();
            for (consumer, item, field) in &rows {
                let capabilities = parse_capabilities(&vault, &format!("acquire:{item}#{field}"))?;
                if let Some(existing) = vault
                    .doc()
                    .get("tokens")
                    .and_then(Value::as_object)
                    .and_then(|tokens| tokens.get(consumer))
                {
                    let same_capabilities = existing.get("capabilities").and_then(Value::as_array)
                        == Some(&capabilities);
                    let same_key = existing.get("workload_public_key").and_then(Value::as_str)
                        == Some(workload_public_key.as_str());
                    if (!same_capabilities || !same_key) && !replace {
                        bail!(
                            "{consumer} differs from the acquisition catalog; pass --replace-capabilities"
                        );
                    }
                }
                registrations.push((consumer.clone(), capabilities));
            }
            let tokens = vault
                .doc_mut()
                .get_mut("tokens")
                .and_then(Value::as_object_mut)
                .context("tokens section")?;
            for (consumer, capabilities) in &registrations {
                tokens.insert(
                    consumer.clone(),
                    json!({
                        "hash": Value::Null,
                        "capabilities": capabilities,
                        "workload_public_key": workload_public_key,
                        "audience": consumer,
                        "expires_at": expires_at,
                    }),
                );
            }
            vault.save()?;
            crate::runtime::audit::append(
                "token-register-acquisitions",
                &json!({
                    "consumers": registrations.iter().map(|(consumer, _)| consumer).collect::<Vec<_>>(),
                    "expires_at": expires_at,
                }),
            )?;
            Ok(Some(json!({
                "ok": true,
                "registered": registrations.len(),
                "expires_at": expires_at,
            })))
        }
        "token-mint" => {
            let consumer = positionals
                .first()
                .context("usage: token-mint <consumer> --capabilities action:item[#field]")?;
            if !exact_component(consumer) {
                bail!("consumer must be one exact name");
            }
            // Many hosts mint concurrently against one authoritative vault.
            // save() is optimistic and refuses on generation drift, so a
            // losing racer re-opens and re-applies instead of surfacing
            // the conflict to callers. Every attempt mints a fresh bearer;
            // only the winner's bearer lands in the report.
            let mut attempt = 0u32;
            loop {
                attempt += 1;
                match mint_once(consumer, flags, attempt) {
                    Ok(report) => return Ok(Some(report)),
                    Err(error)
                        if error.to_string().contains("changed concurrently") && attempt < 5 =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(
                            150 * u64::from(attempt),
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }
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
            let consumer = positionals.first().context(
                "usage: token-verify <consumer> <item-id> --action read [--field field] --token T",
            )?;
            let item = positionals.get(std::iter::once(()).count()).context(
                "usage: token-verify <consumer> <item-id> --action read [--field field] --token T",
            )?;
            let action = flags.get("action").map(String::as_str).unwrap_or("read");
            let presented = flags.get("token").context("--token required")?;
            let allowed = match flags.get("field") {
                Some(field) => {
                    token_allows_field_action(&load()?, consumer, presented, action, item, field)?
                }
                None => token_allows_action(&load()?, consumer, presented, action, item)?,
            };
            Ok(Some(json!({
                "consumer": consumer,
                "action": action,
                "item": item,
                "field": flags.get("field"),
                "allowed": allowed,
            })))
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
                                "capabilities": entry.get("capabilities"),
                                "workload_bound": entry
                                    .get("workload_public_key")
                                    .and_then(Value::as_str)
                                    .is_some(),
                                "audience": entry.get("audience"),
                                "expires_at": entry.get("expires_at"),
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
