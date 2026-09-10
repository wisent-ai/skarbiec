// Answering an approval the provider is waiting on: the operation already
// exists, so this hands one decision back to Weles and records the outcome.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use crate::core::crypto;
use crate::core::vault::Vault;
use crate::runtime::audit;

use super::super::adopt::{adopt_shape_of, trash_adopted_item, AdoptShape};
use super::super::common::{acquire_credential_operation_lock, exact_name, resume_handles};
use super::super::quarantine::enforce_provider_effect;
use super::super::receipt::approval_expired;
use super::super::state::{
    pending_matches_request, refuse_quarantined, request_item_id, update_request,
};
use super::super::wire::{request_payload, run_weles, wire_request, WIRE_VERSION};
use super::super::STATE_QUARANTINED;

pub(in crate::credential) fn resume(
    vault_path: &Path,
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<Value> {
    let allowed = [
        "approval",
        "resume-token",
        "resume-token-file",
        "consumer",
        "operation",
        "as",
        "token-file",
        "local",
    ];
    let usage =
        "usage: credential resume <item-id> --approval <id> --resume-token <token> [--resume-token-file <path>]";
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{usage}");
    }
    let credential_id = args.first().context(usage)?;
    exact_name("credential item id", credential_id, "200".parse()?)?;
    let (approval_id, resume_token) = resume_handles(flags)?;
    let _request_lock = acquire_credential_operation_lock(vault_path)?;
    let request_item = request_item_id(credential_id);
    let vault = Vault::open(vault_path.to_path_buf())?;
    refuse_quarantined(&vault, credential_id, "resume")?;
    let request = vault
        .get_item(&request_item)
        .and_then(request_payload)
        .with_context(|| format!("no credential operation request exists for {credential_id}"))?;
    if request.get("version").and_then(Value::as_str) != Some(WIRE_VERSION) {
        bail!(
            "{credential_id} has a credential operation record from an unsupported wire version; expected {WIRE_VERSION}"
        );
    }
    if request.get("status").and_then(Value::as_str) != Some("needs_human_approval") {
        bail!("{credential_id} has no credential operation waiting for human approval");
    }
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .context("credential operation has no operation")?
        .to_string();
    if let Some(expected) = flags.get("operation") {
        if expected != &operation {
            bail!("{credential_id} is waiting on {operation}, not {expected}");
        }
    }
    if let Some(expected) = flags.get("consumer") {
        if request.get("consumer").and_then(Value::as_str) != Some(expected.as_str()) {
            bail!("{credential_id} is waiting on a different consumer");
        }
    }
    let approval = request
        .get("weles")
        .and_then(|weles| weles.get("approval"))
        .filter(|approval| !approval.is_null())
        .context("the waiting credential operation carries no approval resource")?
        .clone();
    let stored_id = approval
        .get("approval_id")
        .and_then(Value::as_str)
        .context("stored approval has no approval id")?;
    let stored_token = approval
        .get("resume_token")
        .and_then(Value::as_str)
        .context("stored approval has no resume token")?;
    let expires_at = approval
        .get("expires_at")
        .and_then(Value::as_str)
        .context("stored approval has no expiry")?;
    if stored_id != approval_id
        || crypto::sha256_hex(stored_token)? != crypto::sha256_hex(&resume_token)?
    {
        bail!("the presented approval does not match the waiting credential operation");
    }
    if approval_expired(expires_at)? {
        // An expired approval releases the operation instead of leaving a
        // zombie lease behind: the staged candidate goes back, the record
        // stops blocking, and a fresh submit is the only way forward.
        let mut vault = Vault::open(vault_path.to_path_buf())?;
        let field = request
            .get("field")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let writer = request
            .get("consumer")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let request_id = request
            .get("request_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if pending_matches_request(&vault, credential_id, &request_id, &field, &writer) {
            vault.discard_staged_revision(credential_id, &request_id, &field, &writer)?;
        }
        if operation == "adopt"
            && adopt_shape_of(&request).is_ok_and(|shape| shape == AdoptShape::Created)
        {
            trash_adopted_item(&mut vault, credential_id, &request_id, &writer)?;
        }
        update_request(
            vault_path,
            &request_item,
            &request,
            "approval_expired",
            None,
        )?;
        audit::append_sync(
            "credential-approval-expired",
            &json!({
                "credential": credential_id,
                "operation": operation,
                "request_id": request_id,
                "approval_id": approval_id,
            }),
        )?;
        bail!(
            "APPROVAL_EXPIRED: the approval for {credential_id} expired at {expires_at}; the operation was released and must be submitted again"
        );
    }
    let action_log_id = request
        .get("weles")
        .and_then(|weles| weles.get("action_log_id"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let request_id = request
        .get("request_id")
        .and_then(Value::as_str)
        .context("credential operation has no request id")?
        .to_string();
    let wire = wire_request(
        &request,
        "resume",
        action_log_id.as_deref(),
        Some((approval_id.as_str(), resume_token.as_str())),
    )?;
    let response = match run_weles(&wire) {
        Ok(response) => response,
        Err(error) => {
            // Same settlement contract as the submit path: "operation_failed"
            // is the only failure status a later `credential status` settles.
            update_request(
                vault_path,
                &request_item,
                &request,
                "operation_failed",
                None,
            )?;
            return Err(error);
        }
    };
    let response_status = response
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("failed");
    let frozen = enforce_provider_effect(
        vault_path,
        credential_id,
        &operation,
        &request_id,
        &response,
    )?;
    let accepted = !frozen && matches!(response_status, "operation_queued" | "operation_completed");
    let recorded = if frozen {
        STATE_QUARANTINED
    } else if accepted {
        "pending"
    } else {
        response_status
    };
    update_request(
        vault_path,
        &request_item,
        &request,
        recorded,
        Some(&response),
    )?;
    audit::append_sync(
        "credential-operation-resumed",
        &json!({
            "credential": credential_id,
            "operation": operation,
            "request_id": request_id,
            "approval_id": approval_id,
        }),
    )?;
    Ok(json!({
        "ok": accepted,
        "status": recorded,
        "operation": operation,
        "credential": credential_id,
        "request_id": request_id,
        "weles": response,
    }))
}
