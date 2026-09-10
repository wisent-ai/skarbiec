// Writing a grant: minting one declaration, and widening an existing one by a
// single exact field read. Both write the vault, so both are retried against
// a concurrent writer rather than clobbering it.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use std::path::Path;

use super::rules::capabilities::{parse_capabilities, redemption_contract};
use super::lookup::{active, load, now_epoch, token_allows_field_action};
use super::rules::validation::{
    exact_component, exact_resource, read_fixed_token, read_workload_public_key,
};
use crate::core::{crypto, vault_path};

pub(in crate::access::grant) fn issue_once(
    consumer: &str,
    flags: &std::collections::HashMap<String, String>,
    attempt: u32,
) -> anyhow::Result<Value> {
    let _ = attempt;

    let mut vault = load()?;
    let existing_capabilities = vault
        .doc()
        .get("tokens")
        .and_then(Value::as_object)
        .and_then(|tokens| tokens.get(consumer))
        .map(|existing| {
            existing
                .get("capabilities")
                .and_then(Value::as_array)
                .cloned()
                .context("existing grant is not v2; run migrate-v2 first")
        })
        .transpose()?;
    let capabilities = parse_capabilities(
        &vault,
        flags
            .get("capabilities")
            .context("--capabilities is required")?,
        existing_capabilities.as_deref().unwrap_or_default(),
    )?;
    if let Some(existing_capabilities) = &existing_capabilities {
        let same_capabilities = existing_capabilities.len() == capabilities.len()
            && existing_capabilities
                .iter()
                .all(|capability| capabilities.contains(capability));
        let replace_capabilities = flags
            .get("replace-capabilities")
            .is_some_and(|value| value == "true");
        if !same_capabilities && !replace_capabilities {
            bail!(
                "grant issue refuses to change existing capabilities without --replace-capabilities"
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
        "grant-issued",
        &json!({
            "consumer": consumer,
            "capabilities": capabilities,
            "workload_bound": workload_public_key.is_some(),
            "audience": audience,
            "expires_at": expires_at,
        }),
    )?;
    let mut answer = json!({
        "ok": true,
        "consumer": consumer,
        "capabilities": capabilities,
        "workload_bound": workload_public_key.is_some(),
        "audience": audience,
        "expires_at": expires_at,
        "token": generated_token,
    });
    // What `invite` existed to print. An acquire grant hands out no bearer, so
    // an operator who has just declared one holds nothing and has no statement
    // of what the workload does next, and answering it here keeps the
    // declaration and its redemption contract one answer from one command.
    let redeem = redemption_contract(consumer, &capabilities);
    if !redeem.is_empty() {
        answer["redeem"] = json!(redeem);
    }
    Ok(answer)
}

pub(in crate::access::grant) fn ensure_read_once(
    consumer: &str,
    item: &str,
    field: &str,
    token_file: &Path,
) -> Result<Value> {
    if !exact_component(consumer) || !exact_resource(item) || !exact_component(field) {
        bail!("grant ensure requires exact consumer, item, and field names");
    }
    let mut vault = load()?;
    let mut requested = parse_capabilities(&vault, &format!("read:{item}#{field}"), &[])?;
    let capability = requested
        .pop()
        .context("grant ensure produced no capability")?;
    let bearer = read_fixed_token(token_file)?;
    let presented_hash = crypto::sha256_hex(&bearer)?;
    let existing = vault
        .doc()
        .get("tokens")
        .and_then(Value::as_object)
        .and_then(|tokens| tokens.get(consumer))
        .context("consumer has no existing grant")?;
    if !active(existing) {
        bail!("consumer grant is expired or inactive");
    }
    if existing.get("hash").and_then(Value::as_str) != Some(&presented_hash) {
        bail!("token file does not match the consumer's recorded bearer");
    }
    let already_present = existing
        .get("capabilities")
        .and_then(Value::as_array)
        .context("existing grant is not v2; run migrate-v2 first")?
        .contains(&capability);
    let status = if already_present {
        "unchanged"
    } else {
        vault
            .doc_mut()
            .get_mut("tokens")
            .and_then(Value::as_object_mut)
            .and_then(|tokens| tokens.get_mut(consumer))
            .and_then(|grant| grant.get_mut("capabilities"))
            .and_then(Value::as_array_mut)
            .context("existing grant is not v2; run migrate-v2 first")?
            .push(capability.clone());
        vault.save()?;
        crate::runtime::audit::append(
            "grant-ensured-read",
            &json!({
                "consumer": consumer,
                "item": item,
                "field": field,
            }),
        )?;
        "added"
    };

    // A capability sitting in the grant is a weaker claim than a read that
    // succeeds. The serving path also matches the presented bearer, resolves
    // the item, and consults the credential lifecycle, and any of those can
    // refuse a capability that is plainly recorded - which is how this command
    // came to answer `ok` about reads the API was answering 403 to. The
    // decision is therefore exercised here through the same two predicates
    // `/v1/items/read` applies, and the vault it was decided against is named,
    // because this machine runs several brokers over different vault files and
    // a grant recorded in one says nothing about a consumer reading another.
    let vault = load()?;
    let refusal = if !token_allows_field_action(&vault, consumer, &bearer, "read", item, field)? {
        Some("consumer not authorized to read item field")
    } else if field != "context"
        && matches!(
            crate::credential::managed_read(&vault, item, field, consumer)?,
            crate::credential::ManagedRead::Refused
        )
    {
        Some("this revision is not readable by this consumer")
    } else {
        None
    };

    let mut answer = json!({
        "ok": refusal.is_none(),
        "consumer": consumer,
        "capability": capability,
        "status": status,
        "effective": refusal.is_none(),
        "decided_against_vault": vault_path().display().to_string(),
    });
    if let Some(reason) = refusal {
        answer["refusal"] = json!(reason);
    }
    Ok(answer)
}
