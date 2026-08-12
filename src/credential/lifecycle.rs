// The two ways a credential operation reaches Weles: start_operation submits a
// fresh one, resume answers an approval the provider is waiting on.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use crate::core::vault::Vault;
use crate::core::{crypto, inbox};
use crate::runtime::audit;

use super::adopt::{
    adopt_shape_of, read_password_stdin, stage_adopted_candidate, trash_adopted_item, zeroize,
    AdoptShape, AdoptStaging,
};
use super::common::{
    acquire_credential_operation_lock, email_address, exact_name, now_iso, purpose, resume_handles,
};
use super::directory::{cross_check_expectations, resolved_directory, wire_directory};
use super::eligibility::enforce_field_contract;
use super::quarantine::{enforce_provider_effect, enforce_retry_barrier};
use super::receipt::approval_expired;
use super::state::{
    item_revision, lifecycle_state, live_item_exists, pending_matches_request, refuse_quarantined,
    request_item_id, save_request, update_request,
};
use super::wire::{provider_contract, request_payload, run_weles, wire_request, WIRE_VERSION};
use super::{STATE_MANAGED, STATE_QUARANTINED};

pub(super) fn start_operation(
    operation: &str,
    vault_path: &Path,
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<Value> {
    let allowed = [
        "provider",
        "consumer",
        "purpose",
        "account",
        "expect-tenant",
        "expect-object-id",
        "expect-upn",
        "password-stdin",
        "dry-run",
        "local",
    ];
    let usage = format!(
        "usage: credential {operation} <item-id> --provider <provider> --consumer <consumer> [--account <email>] [--expect-tenant <uuid>] [--expect-object-id <uuid>] [--expect-upn <email>] [--purpose <purpose>] [--dry-run]"
    );
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{usage}");
    }
    let password_stdin = flags
        .get("password-stdin")
        .is_some_and(|value| value == "true");
    if operation == "adopt" && !password_stdin {
        bail!(
            "credential adopt requires --password-stdin: the current password is read from stdin and never from argv"
        );
    }
    if operation != "adopt" && password_stdin {
        bail!("--password-stdin is accepted only by credential adopt");
    }
    let credential_id = args.first().context(usage.clone())?;
    let provider = flags.get("provider").context("--provider is required")?;
    let consumer = flags.get("consumer").context("--consumer is required")?;
    exact_name("credential item id", credential_id, "200".parse()?)?;
    exact_name("provider", provider, "128".parse()?)?;
    exact_name("consumer", consumer, "200".parse()?)?;
    let purpose = purpose(flags.get("purpose"), consumer)?;
    let account = email_address("--account", flags.get("account"))?;
    let dry_run = flags.get("dry-run").is_some_and(|value| value == "true");
    if operation == "adopt" && dry_run {
        bail!("credential adopt stages an operator-supplied password and has no dry run");
    }

    // Directory identity and the canonical field are both item contract: read
    // them, cross-check them, never take either as an argument.
    let (directory, field) = {
        let vault = Vault::open(vault_path.to_path_buf())?;
        refuse_quarantined(&vault, credential_id, operation)?;
        let directory = resolved_directory(&vault, credential_id)?;
        cross_check_expectations(flags, credential_id, directory.as_ref())?;
        let field = provider_contract(
            operation,
            provider,
            credential_id,
            account.as_deref(),
            directory.as_ref(),
        )?;
        // The item's own field decides whether it is eligible at all. A
        // provider contract that writes another name is refused here, before
        // the operation lock, the record, or the bridge.
        enforce_field_contract(&vault, credential_id, provider, field)?;
        (directory, field)
    };
    let wire_block = match directory.as_ref() {
        Some(sealed) => Some(wire_directory(sealed)?),
        None => None,
    };

    let request_item = request_item_id(credential_id);
    let _request_lock = if dry_run {
        None
    } else {
        Some(acquire_credential_operation_lock(vault_path)?)
    };
    let mut resumable_request: Option<Value> = None;
    let mut adopt_shape: Option<AdoptShape> = None;
    let mut baseline_revision = u64::MIN;
    if !dry_run {
        let vault = Vault::open(vault_path.to_path_buf())?;
        let live = live_item_exists(&vault, credential_id);
        let managed = live && inbox::managed_by_weles(&vault, credential_id);
        let state = lifecycle_state(&vault, credential_id)?;
        match operation {
            "acquire" if managed => {
                return Ok(json!({
                    "ok": true,
                    "status": "managed",
                    "credential": credential_id,
                    "revision": item_revision(&vault, credential_id),
                }));
            }
            "acquire" if live => {
                bail!(
                    "{credential_id} already exists but has no Weles provenance; refusing to call it acquired"
                );
            }
            "adopt" if state == STATE_MANAGED => {
                bail!(
                    "{credential_id} is already a managed credential; rotate or verify it instead of adopting it"
                );
            }
            "adopt" => {
                if live && !managed {
                    bail!(
                        "{credential_id} exists outside Weles management, and an item can only enter managed state at creation; adopt cannot take it over"
                    );
                }
                if live
                    && inbox::written_by(&vault, credential_id).as_deref()
                        != Some(consumer.as_str())
                {
                    bail!(
                        "{credential_id} is written by a different Weles consumer; credential adopt must name that exact --consumer"
                    );
                }
                adopt_shape = Some(if live {
                    AdoptShape::Staged
                } else {
                    AdoptShape::Created
                });
            }
            "rotate" | "reset" | "verify" | "remove" if !managed => {
                bail!(
                    "{credential_id} is not an active Weles-managed credential; refusing external {operation}"
                );
            }
            "rotate" | "reset" | "verify" | "remove" if state != STATE_MANAGED => {
                bail!(
                    "{credential_id} is {state}, not managed; finish the adoption before {operation}"
                );
            }
            _ => {}
        }
        if let Ok(existing) = vault.get_item(&request_item).and_then(request_payload) {
            enforce_retry_barrier(&existing, credential_id, operation)?;
            if matches!(
                existing.get("status").and_then(Value::as_str),
                Some("submitting" | "pending" | "needs_human_approval")
            ) {
                if existing.get("version").and_then(Value::as_str) != Some(WIRE_VERSION) {
                    bail!(
                        "{credential_id} has a pending request from an unsupported wire version; resolve it before {operation}"
                    );
                }
                let existing_operation = existing
                    .get("operation")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                if existing_operation != operation {
                    bail!(
                        "{credential_id} already has pending {existing_operation}; finish it before {operation}"
                    );
                }
                let identity_matches = existing.get("provider").and_then(Value::as_str)
                    == Some(provider.as_str())
                    && existing.get("consumer").and_then(Value::as_str) == Some(consumer.as_str())
                    && existing.get("purpose").and_then(Value::as_str) == Some(purpose.as_str())
                    && existing.get("account_email").and_then(Value::as_str) == account.as_deref()
                    && existing.get("directory").filter(|value| !value.is_null())
                        == wire_block.as_ref();
                if !identity_matches {
                    bail!(
                        "{credential_id} has a conflicting pending {operation} request with different lifecycle identity"
                    );
                }
                let submitted = existing
                    .get("weles")
                    .and_then(|value| value.get("action_log_id"))
                    .and_then(Value::as_str)
                    .is_some();
                if submitted
                    || existing.get("status").and_then(Value::as_str)
                        == Some("needs_human_approval")
                {
                    return Ok(json!({
                        "ok": true,
                        "status": existing.get("status"),
                        "operation": operation,
                        "credential": credential_id,
                        "request_id": existing.get("request_id"),
                        "weles": existing.get("weles"),
                    }));
                }
                resumable_request = Some(existing);
            }
        }
        // A half-finished adopt keeps the shape it started with: the item it
        // created must not be mistaken for one that existed before.
        if let Some(existing) = resumable_request.as_ref().filter(|_| operation == "adopt") {
            adopt_shape = Some(adopt_shape_of(existing)?);
        }
        baseline_revision = resumable_request
            .as_ref()
            .and_then(|request| request.get("baseline_revision"))
            .and_then(Value::as_u64)
            .unwrap_or_else(|| item_revision(&vault, credential_id).unwrap_or_default());
    }

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
            field,
            consumer,
            request_id: &request_id,
            account: account.as_deref(),
            directory: directory.as_ref(),
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
            "provider": provider,
            "consumer": consumer,
            "purpose": purpose,
            "account_email": account,
            "directory": wire_block,
            "baseline_revision": baseline_revision,
            "field": field,
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
                "provider": provider,
                "consumer": consumer,
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

pub(super) fn resume(
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
