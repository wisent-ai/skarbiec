// The sealed directory contract: the one authority on which principal an item
// speaks for. Written by seal-directory, changed only by reseal, and never
// supplied by a lifecycle caller: `--expect-*` can refuse it, never set it.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::Path;

use crate::access::tokens;
use crate::core::vault::Vault;
use crate::runtime::audit;

use super::common::{
    acquire_credential_operation_lock, client_identity, email_address, exact_name, lowercase_uuid,
    now_iso, safe_string, uuid_shaped,
};
use super::state::{
    context_block, live_item_exists, refuse_quarantined, save_request, seal_item_id, store_context,
};
use super::wire::request_payload;
use super::EXPECTATION_MISMATCH;

// The sealed directory block, exactly as the bridge accepts it on the wire.
pub(super) const DIRECTORY_KEYS: &[&str] = &[
    "provider",
    "tenant_id",
    "principal_object_id",
    "account_upn",
];

pub(super) fn checked_directory(block: &Value) -> Result<Value> {
    let object = block
        .as_object()
        .context("sealed directory contract is not an object")?;
    for key in DIRECTORY_KEYS.iter().copied() {
        if !object.contains_key(key) {
            bail!("sealed directory contract is missing {key}");
        }
    }
    let provider = safe_string(block, "provider").context("sealed directory has no provider")?;
    exact_name("sealed directory provider", &provider, "128".parse()?)?;
    let tenant_id = safe_string(block, "tenant_id").context("sealed directory has no tenant_id")?;
    let principal_object_id = safe_string(block, "principal_object_id")
        .context("sealed directory has no principal_object_id")?;
    if !uuid_shaped(&tenant_id)? || !uuid_shaped(&principal_object_id)? {
        bail!("sealed directory tenant_id and principal_object_id must be lowercase UUIDs");
    }
    let account_upn = email_address(
        "sealed directory account_upn",
        safe_string(block, "account_upn").as_ref(),
    )?
    .context("sealed directory has no account_upn")?;
    Ok(json!({
        "provider": provider,
        "tenant_id": tenant_id,
        "principal_object_id": principal_object_id,
        "account_upn": account_upn,
    }))
}

// The wire block carries exactly the four canonical keys: sealed_at is
// item-local bookkeeping and the bridge rejects it.
pub(super) fn wire_directory(sealed: &Value) -> Result<Value> {
    checked_directory(sealed)
}

pub(super) fn sealed_record(vault: &Vault, credential_id: &str) -> Result<Option<Value>> {
    let seal_item = seal_item_id(credential_id);
    if !live_item_exists(vault, &seal_item) {
        return Ok(None);
    }
    let sealed = vault
        .get_item(&seal_item)
        .and_then(request_payload)
        .with_context(|| format!("read the sealed directory contract of {credential_id}"))?;
    Ok(Some(sealed))
}

// One authority, two copies: the sealed record survives item absence and the
// item context carries the same block once the item exists. A divergence is a
// contract failure, never a preference.
pub(super) fn resolved_directory(vault: &Vault, credential_id: &str) -> Result<Option<Value>> {
    let record = sealed_record(vault, credential_id)?;
    let inside = context_block(vault, credential_id, "directory");
    match (record, inside) {
        (Some(record), Some(inside)) => {
            let sealed = checked_directory(&record)?;
            if sealed != checked_directory(&inside)? {
                bail!(
                    "DIRECTORY_CONTRACT_DIVERGED: {credential_id} and its sealed directory record name different identities; reseal it before any lifecycle operation"
                );
            }
            Ok(Some(with_sealed_at(&sealed, &record, &inside)))
        }
        (Some(record), None) => {
            let sealed = checked_directory(&record)?;
            Ok(Some(with_sealed_at(&sealed, &record, &record)))
        }
        (None, Some(inside)) => {
            let sealed = checked_directory(&inside)?;
            Ok(Some(with_sealed_at(&sealed, &inside, &inside)))
        }
        (None, None) => Ok(None),
    }
}

pub(super) fn with_sealed_at(sealed: &Value, first: &Value, second: &Value) -> Value {
    let sealed_at = safe_string(first, "sealed_at").or_else(|| safe_string(second, "sealed_at"));
    let mut block = sealed.clone();
    if let (Some(object), Some(sealed_at)) = (block.as_object_mut(), sealed_at) {
        object.insert("sealed_at".to_string(), Value::String(sealed_at));
    }
    block
}

// `--expect-*` never supplies identity: it only refuses to proceed when the
// sealed contract is not the one the caller believes it is.
pub(super) fn cross_check_expectations(
    flags: &HashMap<String, String>,
    credential_id: &str,
    directory: Option<&Value>,
) -> Result<()> {
    let expectations = [
        ("--expect-tenant", "tenant_id", "tenant"),
        ("--expect-object-id", "principal_object_id", "object-id"),
        ("--expect-upn", "account_upn", "upn"),
    ];
    for (flag, key, suffix) in expectations {
        let raw = flags.get(&format!("expect-{suffix}"));
        let expected = match key {
            "account_upn" => email_address(flag, raw)?,
            _ => lowercase_uuid(flag, raw)?,
        };
        let Some(expected) = expected else {
            continue;
        };
        let sealed = directory
            .and_then(|block| block.get(key))
            .and_then(Value::as_str);
        if sealed != Some(expected.as_str()) {
            bail!(
                "{EXPECTATION_MISMATCH}: {flag} does not match the sealed directory contract of {credential_id}"
            );
        }
    }
    Ok(())
}

pub(super) fn expectation_body(flags: &HashMap<String, String>) -> Result<Option<Value>> {
    let mut expect = Map::new();
    if let Some(tenant) = lowercase_uuid("--expect-tenant", flags.get("expect-tenant"))? {
        expect.insert("tenant_id".to_string(), json!(tenant));
    }
    if let Some(object_id) = lowercase_uuid("--expect-object-id", flags.get("expect-object-id"))? {
        expect.insert("principal_object_id".to_string(), json!(object_id));
    }
    if let Some(upn) = email_address("--expect-upn", flags.get("expect-upn"))? {
        expect.insert("account_upn".to_string(), json!(upn));
    }
    if expect.is_empty() {
        return Ok(None);
    }
    Ok(Some(Value::Object(expect)))
}

pub(super) fn seal_directory(
    vault_path: &Path,
    flags: &HashMap<String, String>,
    args: &[String],
    reseal: bool,
) -> Result<Value> {
    let command = if reseal { "reseal" } else { "seal-directory" };
    let allowed = [
        "provider",
        "tenant",
        "object-id",
        "account-upn",
        "as",
        "token-file",
        "local",
    ];
    let usage = format!(
        "usage: credential {command} <item-id> --provider <provider> --tenant <uuid> --object-id <uuid> --account-upn <email>{}",
        if reseal {
            " --as <consumer> --token-file <path>"
        } else {
            ""
        }
    );
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{usage}");
    }
    let credential_id = args.first().context(usage.clone())?;
    exact_name("credential item id", credential_id, "200".parse()?)?;
    let provider = flags.get("provider").context("--provider is required")?;
    exact_name("provider", provider, "128".parse()?)?;
    let tenant_id =
        lowercase_uuid("--tenant", flags.get("tenant"))?.context("--tenant is required")?;
    let principal_object_id = lowercase_uuid("--object-id", flags.get("object-id"))?
        .context("--object-id is required")?;
    let account_upn = email_address("--account-upn", flags.get("account-upn"))?
        .context("--account-upn is required")?;
    let sealed = json!({
        "provider": provider,
        "tenant_id": tenant_id,
        "principal_object_id": principal_object_id,
        "account_upn": account_upn,
        "sealed_at": now_iso(),
    });
    // Reject a malformed block before anything is written.
    checked_directory(&sealed)?;
    let _lock = acquire_credential_operation_lock(vault_path)?;
    let mut vault = Vault::open(vault_path.to_path_buf())?;
    refuse_quarantined(&vault, credential_id, command)?;
    if reseal {
        let (consumer, token) = client_identity(flags)?;
        if !tokens::token_allows_action(&vault, &consumer, &token, "reseal", credential_id)? {
            bail!("{consumer} holds no reseal capability for {credential_id}");
        }
    } else if resolved_directory(&vault, credential_id)?.is_some() {
        bail!(
            "{credential_id} already carries a sealed directory contract; changing it requires credential reseal and a reseal capability"
        );
    }
    let seal_item = seal_item_id(credential_id);
    save_request(vault_path, &seal_item, &sealed)?;
    vault = Vault::open(vault_path.to_path_buf())?;
    if live_item_exists(&vault, credential_id) {
        store_context(&mut vault, credential_id, &[("directory", sealed.clone())])?;
    }
    audit::append_sync(
        if reseal {
            "credential-directory-resealed"
        } else {
            "credential-directory-sealed"
        },
        &json!({
            "credential": credential_id,
            "provider": provider,
            "tenant_id": sealed.get("tenant_id"),
            "principal_object_id": sealed.get("principal_object_id"),
            "account_upn": sealed.get("account_upn"),
        }),
    )?;
    Ok(json!({
        "ok": true,
        "status": "sealed",
        "credential": credential_id,
        "directory": sealed,
        "resealed": reseal,
    }))
}
