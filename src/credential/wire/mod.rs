// The wire contract with the Weles credential bridge: the accepted version,
// the request key whitelist, response sanitization, the bridge invocation, and
// the per-provider contract each request must satisfy.

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::core::schema;

mod bridge;
mod providers;

pub(super) use bridge::run_weles;
pub(super) use providers::{
    declared_signup_origin, generic_credential_id, generic_provider, generic_provider_slug,
    operation_contract_field, provider_contract, GENERIC_PROVIDER_SHAPE,
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
    "signup_origin",
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

pub(super) fn request_payload(request: Value) -> Result<Value> {
    schema::field(&request, "value")
        .cloned()
        .context("credential operation record has no canonical value field")
}

// The canonical envelope one lifecycle-owned record is stored in. `kind` is the
// record's declaration of which family it belongs to, so it is supplied rather
// than assumed: the operation record and the sealed directory contract share
// this shape and are not the same thing.
pub(super) fn record_envelope(kind: &str, record: &Value) -> Value {
    json!({
        "schema": schema::ITEM_SCHEMA,
        "kind": kind,
        "fields": {"value": record},
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
