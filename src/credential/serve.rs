// Serve-side entry points behind `/v1/credential/operations`. The provider and
// the account are item contract, never caller input, so no request body names
// them.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use crate::core::vault::Vault;

use super::common::{exact_name, present, safe_string};
use super::directory::resolved_directory;
use super::lifecycle::{resume, start_operation};
use super::state::{context_string, request_item_id};
use super::status::status_once;
use super::wire::{generic_provider_slug, request_payload, GENERIC_PROVIDER_SHAPE};
use super::{ACCOUNT_PROVIDER, REMOTE_OPERATIONS};

pub(crate) fn endpoint_item(body: &Value) -> Result<String> {
    let item = safe_string(body, "item").context("credential operation request needs an item")?;
    exact_name("credential item id", &item, "200".parse()?)?;
    Ok(item)
}

pub(crate) fn exact_credential_item(value: &str) -> Result<String> {
    exact_name("credential item id", value, "200".parse()?)?;
    Ok(value.to_string())
}

// `POST /v1/credential/operations`. The provider and the account are item
// contract, never caller input, so the body names neither.
pub(crate) fn submit_from_endpoint(vault_path: &Path, body: &Value) -> Result<Value> {
    let object = body
        .as_object()
        .context("credential operation request must be an object")?;
    let allowed = [
        "item",
        "operation",
        "consumer",
        "purpose",
        "signup_origin",
        "expect",
        "approval",
        "resume_token",
    ];
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("credential operation request carries unknown fields");
    }
    let credential_id = endpoint_item(body)?;
    let mut flags: HashMap<String, String> = HashMap::new();
    if present(body, "approval") || present(body, "resume_token") {
        let approval_id = safe_string(body, "approval")
            .context("resuming a credential operation requires the approval id")?;
        let resume_token = safe_string(body, "resume_token")
            .context("resuming a credential operation requires the resume token")?;
        flags.insert("approval".to_string(), approval_id);
        flags.insert("resume-token".to_string(), resume_token);
        if let Some(operation) = safe_string(body, "operation") {
            flags.insert("operation".to_string(), operation);
        }
        if let Some(consumer) = safe_string(body, "consumer") {
            flags.insert("consumer".to_string(), consumer);
        }
        return resume(vault_path, &flags, &[credential_id]);
    }
    let operation = safe_string(body, "operation")
        .context("credential operation request needs an operation")?;
    if !REMOTE_OPERATIONS.contains(&operation.as_str()) {
        bail!(
            "{operation} is not available through the canonical endpoint; credential adopt reads the current password from operator stdin and runs with --local"
        );
    }
    let consumer =
        safe_string(body, "consumer").context("credential operation request needs a consumer")?;
    let (provider, account) = {
        let vault = Vault::open(vault_path.to_path_buf())?;
        let directory = resolved_directory(&vault, &credential_id)?;
        let record = vault
            .get_item(&request_item_id(&credential_id))
            .and_then(request_payload)
            .ok();
        let provider = directory
            .as_ref()
            .and_then(|block| block.get("provider"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                record
                    .as_ref()
                    .and_then(|record| record.get("provider"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            // A credential nobody holds yet carries no provider, and a sealed
            // directory contract is only meaningful for the identity provider,
            // so a first acquire would have had nothing to name. An item named
            // after a generic provider slug is that provider's: the provider is
            // still item contract, read from the item's own name, never from
            // the request body.
            .or_else(|| {
                (operation == "acquire" && generic_provider_slug(&credential_id))
                    .then(|| credential_id.clone())
            })
            .with_context(|| {
                format!(
                    "{credential_id} has no sealed directory contract and no earlier credential operation, so its provider is unknown; seal the directory first, or name the item after a generic provider slug ({GENERIC_PROVIDER_SHAPE}) to acquire one"
                )
            })?;
        let account = record
            .as_ref()
            .and_then(|record| record.get("account_email"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| context_string(&vault, &credential_id, "account_ref"));
        (provider, account)
    };
    flags.insert("provider".to_string(), provider.clone());
    flags.insert("consumer".to_string(), consumer);
    if let Some(purpose) = safe_string(body, "purpose") {
        flags.insert("purpose".to_string(), purpose);
    }
    if let Some(origin) = safe_string(body, "signup_origin") {
        flags.insert("signup-origin".to_string(), origin);
    }
    if provider == ACCOUNT_PROVIDER {
        flags.insert(
            "account".to_string(),
            account.with_context(|| {
                format!("{credential_id} has no recorded account address for {ACCOUNT_PROVIDER}")
            })?,
        );
    }
    if let Some(expect) = body.get("expect") {
        let expect = expect
            .as_object()
            .context("credential operation expectations must be an object")?;
        for (key, flag) in [
            ("tenant_id", "expect-tenant"),
            ("principal_object_id", "expect-object-id"),
            ("account_upn", "expect-upn"),
        ] {
            if let Some(value) = expect.get(key).and_then(Value::as_str) {
                flags.insert(flag.to_string(), value.to_string());
            }
        }
        if expect
            .keys()
            .any(|key| !["tenant_id", "principal_object_id", "account_upn"].contains(&key.as_str()))
        {
            bail!("credential operation expectations carry unknown fields");
        }
    }
    start_operation(&operation, vault_path, &flags, &[credential_id])
}

// `GET /v1/credential/operations/<item>`.
pub(crate) fn status_from_endpoint(vault_path: &Path, credential_id: &str) -> Result<Value> {
    let credential_id = exact_credential_item(credential_id)?;
    status_once(vault_path, &[credential_id])
}
