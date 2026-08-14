// The wire contract with the Weles credential bridge: the accepted version,
// the request key whitelist, response sanitization, the bridge invocation, and
// the per-provider contract each request must satisfy.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use wisent_errors::trim_detail;

use crate::core::schema;

use super::common::{
    checked_bool, checked_code, checked_enum, checked_host, checked_uuid, effective_uid,
    safe_string,
};
use super::receipt::{checked_approval, checked_receipt, receipt_matches, DIRECTORY_IDENTITY_KEYS};
use super::{
    ACCOUNT_PROVIDER, EXPECTATION_MISMATCH, IDENTITY_OPERATIONS, IDENTITY_PROVIDER,
    PROVIDER_EFFECTS, REQUEST_KIND, RESPONSE_PHASES, RESPONSE_STATUSES, ROLLBACK_STATUSES,
};

pub(super) const WIRE_VERSION: &str = "skarbiec.credential-operation.v3";
pub(super) const BRIDGE_ENV: &str = "SKARBIEC_WELES_CREDENTIAL_COMMAND";

// The bridge rejects any request key it does not know, so the submitted object
// is built by whitelist and local bookkeeping never leaves Skarbiec.
pub(super) const WIRE_KEYS: &[&str] = &[
    "version",
    "request_id",
    "mode",
    "action_log_id",
    "credential_id",
    "operation",
    "provider",
    "consumer",
    "purpose",
    "account_email",
    "directory",
    "approval_id",
    "resume_token",
    "baseline_revision",
    "field",
    "status",
    "created_at",
    "dry_run",
];

// Sanitized Weles diagnostics lifted to the top level of the emitted status.
pub(super) const DIAGNOSTIC_KEYS: &[&str] = &[
    "code",
    "phase",
    "retryable",
    "provider_effect",
    "rollback_status",
    "execution_host",
    "tenant_id",
    "principal_object_id",
    "approval",
];

pub(super) fn checked_bridge() -> Result<PathBuf> {
    let configured =
        std::env::var(BRIDGE_ENV).with_context(|| format!("{BRIDGE_ENV} is not set"))?;
    let path = Path::new(configured.trim());
    if !path.is_absolute() {
        bail!("{BRIDGE_ENV} must be an absolute path");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {BRIDGE_ENV} executable {}", path.display()))?;
    let unsafe_bits = u32::from_str_radix("022", "8".parse()?)?;
    let owner_execute = u32::from_str_radix("100", "8".parse()?)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid()?
        || metadata.permissions().mode() & unsafe_bits != u32::MIN
        || metadata.permissions().mode() & owner_execute == u32::MIN
    {
        bail!("{BRIDGE_ENV} must be an owner-controlled executable regular file");
    }
    fs::canonicalize(path).with_context(|| format!("canonicalize {BRIDGE_ENV}"))
}

pub(super) fn sanitized_response(value: &Value) -> Result<Value> {
    // A peer that names a version is naming the protocol it speaks: a
    // different one is a different contract, never a response we may read.
    if let Some(version) = value.get("version").filter(|version| !version.is_null()) {
        if version.as_str() != Some(WIRE_VERSION) {
            bail!("Weles response names an unsupported wire version; expected {WIRE_VERSION}");
        }
    }
    let status = safe_string(value, "status").context("Weles response missing status")?;
    if !RESPONSE_STATUSES.contains(&status.as_str()) {
        bail!("Weles returned unsupported credential-operation status");
    }
    let approval = checked_approval(value)?;
    if status == "needs_human_approval" && approval.is_none() {
        bail!("Weles asked for human approval without an approval resource to resume");
    }
    Ok(json!({
        "status": status,
        "operation": safe_string(value, "operation"),
        "provider": safe_string(value, "provider"),
        "url": safe_string(value, "url"),
        "build_id": safe_string(value, "buildId"),
        "action_log_id": safe_string(value, "actionLogId"),
        "source_action_log_id": safe_string(value, "sourceActionLogId"),
        "flow_name": safe_string(value, "flowName"),
        "vault_item_id": safe_string(value, "vaultItemId"),
        "message": safe_string(value, "message"),
        "code": checked_code(value)?,
        "phase": checked_enum(value, "phase", RESPONSE_PHASES)?,
        "retryable": checked_bool(value, "retryable")?,
        "provider_effect": checked_enum(value, "providerEffect", PROVIDER_EFFECTS)?,
        "rollback_status": checked_enum(value, "rollbackStatus", ROLLBACK_STATUSES)?,
        "execution_host": checked_host(value)?,
        "tenant_id": checked_uuid(value, "tenantId")?,
        "principal_object_id": checked_uuid(value, "principalObjectId")?,
        "approval": approval,
        "receipt": checked_receipt(value)?,
    }))
}

// Bridge stderr is operator-facing diagnostics, never secret material: strip
// control characters, collapse whitespace, and bound it before it reaches an
// error message. Collapsing is skarbiec's own rule -- a bridge writes progress
// lines -- but the bound is the fleet's, from `wisent-errors`.
pub(super) fn sanitized_diagnostics(raw: &[u8]) -> String {
    let max: usize = "512".parse().unwrap_or_default();
    let collapsed = String::from_utf8_lossy(raw)
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");
    trim_detail(&collapsed, max)
}

pub(super) fn run_weles(request: &Value) -> Result<Value> {
    let executable = checked_bridge()?;
    let mut child = Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start Weles credential acquisition bridge")?;
    // Drain stderr concurrently so a chatty bridge cannot deadlock on a full
    // pipe while we are still reading its stdout.
    let mut errors = child.stderr.take().context("open Weles bridge stderr")?;
    let diagnostic_max: u64 = "4096".parse()?;
    let diagnostics = std::thread::spawn(move || {
        let mut captured = Vec::new();
        let _ = (&mut errors)
            .take(diagnostic_max)
            .read_to_end(&mut captured);
        let _ = std::io::copy(&mut errors, &mut std::io::sink());
        captured
    });
    child
        .stdin
        .take()
        .context("open Weles bridge stdin")?
        .write_all(&serde_json::to_vec(request)?)?;

    let max: u64 = "65536".parse()?;
    let extra: u64 = "1".parse()?;
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .context("open Weles bridge stdout")?
        .take(max.saturating_add(extra))
        .read_to_end(&mut output)?;
    if u64::try_from(output.len())? > max {
        let _ = child.kill();
        let _ = child.wait();
        bail!("Weles credential acquisition response exceeded size limit");
    }
    let status = child
        .wait()
        .context("wait for Weles credential acquisition bridge")?;
    let detail = sanitized_diagnostics(&diagnostics.join().unwrap_or_default());
    if !status.success() {
        if detail.is_empty() {
            bail!("Weles credential-operation bridge exited with {status} and no diagnostics");
        }
        bail!("Weles credential-operation bridge exited with {status}: {detail}");
    }
    let parsed: Value = serde_json::from_slice(&output).with_context(|| {
        if detail.is_empty() {
            "Weles response is not JSON".to_string()
        } else {
            format!("Weles response is not JSON: {detail}")
        }
    })?;
    output.fill(u8::MIN);
    let response = sanitized_response(&parsed)?;
    let same_identity = response.get("operation").and_then(Value::as_str)
        == request.get("operation").and_then(Value::as_str)
        && response.get("provider").and_then(Value::as_str)
            == request.get("provider").and_then(Value::as_str)
        && response.get("vault_item_id").and_then(Value::as_str)
            == request.get("credential_id").and_then(Value::as_str);
    if !same_identity {
        bail!("Weles credential-operation response identity mismatch");
    }
    // The sealed directory block is the only identity the response may echo.
    let directory = request.get("directory").filter(|value| !value.is_null());
    if let Some(directory) = directory {
        for key in DIRECTORY_IDENTITY_KEYS
            .iter()
            .copied()
            .filter(|key| *key != "account_upn")
        {
            let returned = response.get(key).and_then(Value::as_str);
            if returned.is_some() && returned != directory.get(key).and_then(Value::as_str) {
                bail!("Weles credential-operation response {key} does not match the sealed directory contract");
            }
        }
    }
    if let Some(receipt) = response.get("receipt").filter(|value| !value.is_null()) {
        let operation = request
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let request_id = request
            .get("request_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !receipt_matches(receipt, directory, operation, request_id) {
            bail!(
                "Weles credential-operation receipt names another principal, request, or operation"
            );
        }
    }
    let response_status = response
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let action_log_id = response.get("action_log_id").and_then(Value::as_str);
    if response_status == "operation_queued" && action_log_id.is_none() {
        bail!("queued Weles credential operation is missing its action log id");
    }
    if request.get("mode").and_then(Value::as_str) == Some("status") {
        let requested_action_log_id = request.get("action_log_id").and_then(Value::as_str);
        let chained_from = response.get("source_action_log_id").and_then(Value::as_str);
        if action_log_id != requested_action_log_id && chained_from != requested_action_log_id {
            bail!("Weles credential-operation status task identity mismatch");
        }
    }
    Ok(response)
}

pub(super) fn request_payload(request: Value) -> Result<Value> {
    schema::field(&request, "value")
        .cloned()
        .context("credential operation record has no canonical value field")
}

pub(super) fn request_envelope(request: &Value) -> Value {
    json!({
        "schema": schema::ITEM_SCHEMA,
        "kind": REQUEST_KIND,
        "fields": {"value": request},
        "context": {},
    })
}

pub(super) fn wire_request(
    record: &Value,
    mode: &str,
    action_log_id: Option<&str>,
    approval: Option<(&str, &str)>,
) -> Result<Value> {
    let object = record
        .as_object()
        .context("credential request is not an object")?;
    let mut wire = Map::new();
    for key in WIRE_KEYS.iter().copied() {
        wire.insert(
            key.to_string(),
            object.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    wire.insert("mode".to_string(), json!(mode));
    wire.insert("status".to_string(), json!("pending"));
    wire.insert(
        "action_log_id".to_string(),
        action_log_id
            .map(|id| Value::String(id.to_string()))
            .unwrap_or(Value::Null),
    );
    let (approval_id, resume_token) = match approval {
        Some((id, token)) => (
            Value::String(id.to_string()),
            Value::String(token.to_string()),
        ),
        None => (Value::Null, Value::Null),
    };
    wire.insert("approval_id".to_string(), approval_id);
    wire.insert("resume_token".to_string(), resume_token);
    if mode == "resume" {
        wire.insert("dry_run".to_string(), Value::Bool(false));
    }
    Ok(Value::Object(wire))
}

// The one field a provider's credential contract writes. `provider_contract`
// decides the whole contract per operation; this is the field half of it on
// its own, so eligibility and the operation itself can never disagree about
// which name a lifecycle would write.
pub(super) fn contract_field(provider: &str) -> &'static str {
    match provider {
        IDENTITY_PROVIDER | ACCOUNT_PROVIDER => "password",
        _ => "api_key",
    }
}

// One exact provider contract per credential: the sealed directory block, the
// canonical field, and the permitted operations are decided together.
pub(super) fn provider_contract(
    operation: &str,
    provider: &str,
    credential_id: &str,
    account: Option<&str>,
    directory: Option<&Value>,
) -> Result<&'static str> {
    if let Some(sealed) = directory
        .and_then(|block| block.get("provider"))
        .and_then(Value::as_str)
    {
        if sealed != provider {
            bail!(
                "{EXPECTATION_MISMATCH}: {credential_id} is sealed for provider {sealed}, not {provider}"
            );
        }
    }
    match provider {
        IDENTITY_PROVIDER => {
            if directory.is_none() {
                bail!(
                    "{credential_id} has no sealed directory contract; run credential seal-directory {credential_id} --provider {IDENTITY_PROVIDER} --tenant <uuid> --object-id <uuid> --account-upn <email> before any lifecycle operation"
                );
            }
            if account.is_some() {
                bail!(
                    "--account is not accepted for {IDENTITY_PROVIDER}: the account address is part of the sealed directory contract"
                );
            }
            if !IDENTITY_OPERATIONS.contains(&operation) {
                bail!(
                    "{IDENTITY_PROVIDER} supports only adopt, rotate, verify, or reset; refusing {operation}"
                );
            }
            Ok(contract_field(provider))
        }
        ACCOUNT_PROVIDER => {
            if account.is_none() {
                bail!("{ACCOUNT_PROVIDER} credential operations require --account <email>");
            }
            if operation == "reset" {
                bail!("reset requires a directory provider; {ACCOUNT_PROVIDER} cannot reset an unknown current password");
            }
            Ok(contract_field(provider))
        }
        other => {
            if directory.is_some() {
                bail!(
                    "a sealed directory contract is only meaningful for {IDENTITY_PROVIDER}; {credential_id} names {other}"
                );
            }
            if operation == "reset" {
                bail!("provider {other} has no credential reset contract");
            }
            Ok(contract_field(provider))
        }
    }
}
