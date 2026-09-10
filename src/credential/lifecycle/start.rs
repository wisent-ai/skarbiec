// Submitting one credential operation: record the request, hand it to Weles,
// and write down exactly what came back.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use crate::core::crypto;
use crate::runtime::audit;

use super::super::adopt::{
    read_password_stdin, stage_adopted_candidate, zeroize, AdoptShape, AdoptStaging,
};
use super::super::common::{acquire_credential_operation_lock, now_iso};
use super::super::quarantine::enforce_provider_effect;
use super::super::state::{request_item_id, save_request, update_request};
use super::super::wire::{run_weles, wire_request, WIRE_VERSION};
use super::super::STATE_QUARANTINED;
use super::inputs::read_submission;
use super::preflight::{preflight, Preflight};

pub(in crate::credential) fn start_operation(
    operation: &str,
    vault_path: &Path,
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<Value> {
    let submission = read_submission(operation, vault_path, flags, args)?;
    let credential_id = submission.credential_id;
    let dry_run = submission.dry_run;
    let request_item = request_item_id(credential_id);
    let _request_lock = if dry_run {
        None
    } else {
        Some(acquire_credential_operation_lock(vault_path)?)
    };
    let proceed = match preflight(vault_path, &submission)? {
        Preflight::Answered(answer) => return Ok(answer),
        Preflight::Proceed(proceed) => proceed,
    };
    let resumable_request = proceed.resumable_request;
    let adopt_shape = proceed.adopt_shape;
    let mut baseline_revision = proceed.baseline_revision;

    let request_id = match resumable_request
        .as_ref()
        .and_then(|request| request.get("request_id"))
        .and_then(Value::as_str)
    {
        Some(existing) => existing.to_string(),
        None => crypto::random_token()?,
    };

    // adopt stages the operator's password before the request is recorded, so
    // the wire reports exactly the revision Weles will read against.
    if let Some(shape) = adopt_shape {
        let staging = AdoptStaging {
            shape,
            credential_id,
            field: submission.field,
            consumer: submission.consumer,
            request_id: &request_id,
            account: submission.account.as_deref(),
            directory: submission.directory.as_ref(),
        };
        let candidate = read_password_stdin()?;
        let staged = stage_adopted_candidate(vault_path, &staging, &candidate);
        zeroize(candidate);
        baseline_revision = staged?;
    }

    let request = resumable_request.unwrap_or_else(|| {
        json!({
            "version": WIRE_VERSION,
            "mode": "submit",
            "action_log_id": Value::Null,
            "request_id": request_id,
            "operation": operation,
            "credential_id": credential_id,
            "provider": submission.provider,
            "consumer": submission.consumer,
            "purpose": submission.purpose,
            "account_email": submission.account,
            "signup_origin": submission.signup_origin,
            "directory": submission.wire_block,
            "baseline_revision": baseline_revision,
            "field": submission.field,
            "status": "submitting",
            "created_at": now_iso(),
            "dry_run": dry_run,
            "adopt_shape": adopt_shape.map(AdoptShape::as_str),
        })
    });

    if !dry_run {
        save_request(vault_path, &request_item, &request)?;
        if let Err(error) = audit::append_sync(
            "credential-operation-request",
            &json!({
                "request_id": request_id,
                "operation": operation,
                "credential": credential_id,
                "provider": submission.provider,
                "consumer": submission.consumer,
            }),
        ) {
            // A submit that never reached Weles is an operation failure, not a
            // distinct vocabulary: only "operation_failed" lets a later
            // `credential status` settle the staged revision, and plain
            // "failed" wedges the item with no path back.
            update_request(
                vault_path,
                &request_item,
                &request,
                "operation_failed",
                None,
            )?;
            return Err(error);
        }
    }

    let submit_request = wire_request(&request, "submit", None, None)?;
    let response = match run_weles(&submit_request) {
        Ok(response) => response,
        Err(error) if !dry_run => {
            update_request(
                vault_path,
                &request_item,
                &request,
                "operation_failed",
                None,
            )?;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let response_status = response
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("failed");
    if dry_run {
        return Ok(json!({
            "ok": response_status == "operation_plan",
            "operation": operation,
            "credential": credential_id,
            "request_id": request_id,
            "weles": response,
        }));
    }

    let frozen =
        enforce_provider_effect(vault_path, credential_id, operation, &request_id, &response)?;
    let accepted = !frozen && matches!(response_status, "operation_queued" | "operation_completed");
    let recorded = if frozen {
        STATE_QUARANTINED
    } else if response_status == "operation_completed" {
        "operation_completed"
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
    Ok(json!({
        "ok": accepted,
        "status": recorded,
        "operation": operation,
        "credential": credential_id,
        "request_id": request_id,
        "weles": response,
    }))
}
