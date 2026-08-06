// Approval and receipt objects. Both are all-or-nothing resources: a partial
// approval cannot be resumed and a partial receipt proves nothing, so either
// shape is a protocol violation rather than noise.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use super::common::{
    checked_enum, checked_timestamp, checked_uuid, exact_name, hex_digest, now_iso, opaque_handle,
    present, safe_string, timestamp_shaped, zulu_seconds,
};
use super::{OPERATIONS, PROVIDER_EFFECTS, RESPONSE_PHASES};

// Receipt fields that must name the same principal as the sealed contract.
pub(super) const DIRECTORY_IDENTITY_KEYS: &[&str] =
    &["tenant_id", "principal_object_id", "account_upn"];

// An expired approval releases the operation instead of resuming it, so a
// clock we cannot read is a refusal, never an assumption.
pub(super) fn approval_expired(expires_at: &str) -> Result<bool> {
    let now = now_iso();
    if !timestamp_shaped(&now) {
        bail!("cannot read the current time to check the approval window");
    }
    if !timestamp_shaped(expires_at) {
        bail!("approval expiry is not an ISO 8601 zulu timestamp");
    }
    Ok(zulu_seconds(expires_at) <= zulu_seconds(&now))
}

// An approval is a resource: all six fields or no object at all, because a
// partial approval cannot be resumed.
pub(super) fn checked_approval(value: &Value) -> Result<Option<Value>> {
    if !present(value, "approval") {
        return Ok(None);
    }
    let approval = value
        .get("approval")
        .filter(|approval| approval.is_object())
        .context("Weles response approval must be an object")?;
    let approval_id =
        safe_string(approval, "approval_id").context("approval is missing approval_id")?;
    let resume_token =
        safe_string(approval, "resume_token").context("approval is missing resume_token")?;
    opaque_handle("approval_id", &approval_id, "64".parse()?)?;
    opaque_handle("resume_token", &resume_token, "128".parse()?)?;
    let phase = checked_enum(approval, "phase", RESPONSE_PHASES)?
        .context("approval is missing an accepted phase")?;
    let provider_effect = checked_enum(approval, "provider_effect", PROVIDER_EFFECTS)?
        .context("approval is missing an accepted provider_effect")?;
    let expires_at =
        checked_timestamp(approval, "expires_at")?.context("approval is missing expires_at")?;
    let instruction = safe_string(approval, "instruction")
        .filter(|instruction| !instruction.is_empty())
        .context("approval is missing a bounded instruction")?;
    Ok(Some(json!({
        "approval_id": approval_id,
        "phase": phase,
        "provider_effect": provider_effect,
        "expires_at": expires_at,
        "resume_token": resume_token,
        "instruction": instruction,
    })))
}

// The receipt answers "was exactly this principal rotated" without reading a
// mailbox: all ten fields or a protocol violation.
pub(super) fn checked_receipt(value: &Value) -> Result<Option<Value>> {
    if !present(value, "receipt") {
        return Ok(None);
    }
    let receipt = value
        .get("receipt")
        .filter(|receipt| receipt.is_object())
        .context("Weles response receipt must be an object")?;
    let tenant_id = checked_uuid(receipt, "tenant_id")?.context("receipt is missing tenant_id")?;
    let principal_object_id = checked_uuid(receipt, "principal_object_id")?
        .context("receipt is missing principal_object_id")?;
    let account_upn = safe_string(receipt, "account_upn")
        .map(|upn| upn.to_lowercase())
        .context("receipt is missing account_upn")?;
    let operation = checked_enum(receipt, "operation", OPERATIONS)?
        .context("receipt is missing an accepted operation")?;
    let request_id = safe_string(receipt, "request_id").context("receipt is missing request_id")?;
    let evidence_digest =
        safe_string(receipt, "evidence_digest").context("receipt is missing evidence_digest")?;
    if !hex_digest(&request_id)? || !hex_digest(&evidence_digest)? {
        bail!("receipt request_id and evidence_digest must be 64 hexadecimal characters");
    }
    let host_max: usize = "128".parse()?;
    let execution_host = safe_string(receipt, "execution_host")
        .filter(|host| !host.is_empty() && host.len() <= host_max)
        .context("receipt is missing a bounded execution_host")?;
    let changed_at = match receipt.get("changed_at") {
        Some(Value::Null) => Value::Null,
        Some(_) => Value::String(
            checked_timestamp(receipt, "changed_at")?
                .context("receipt changed_at must be null or a timestamp")?,
        ),
        None => bail!("receipt is missing changed_at"),
    };
    let verified_at =
        checked_timestamp(receipt, "verified_at")?.context("receipt is missing verified_at")?;
    let action_log_id =
        safe_string(receipt, "action_log_id").context("receipt is missing action_log_id")?;
    exact_name("receipt action_log_id", &action_log_id, "200".parse()?)?;
    Ok(Some(json!({
        "tenant_id": tenant_id,
        "principal_object_id": principal_object_id,
        "account_upn": account_upn,
        "operation": operation,
        "request_id": request_id,
        "evidence_digest": evidence_digest,
        "execution_host": execution_host,
        "changed_at": changed_at,
        "verified_at": verified_at,
        "action_log_id": action_log_id,
    })))
}

// A receipt for another principal, request, or operation is a protocol
// violation, not noise.
pub(super) fn receipt_matches(
    receipt: &Value,
    directory: Option<&Value>,
    operation: &str,
    request_id: &str,
) -> bool {
    receipt.get("operation").and_then(Value::as_str) == Some(operation)
        && receipt.get("request_id").and_then(Value::as_str) == Some(request_id)
        && DIRECTORY_IDENTITY_KEYS.iter().all(|key| {
            receipt.get(key).and_then(Value::as_str)
                == directory
                    .and_then(|block| block.get(key))
                    .and_then(Value::as_str)
        })
}
