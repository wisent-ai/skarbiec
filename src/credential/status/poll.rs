// One poll of one credential operation: read the record, ask Weles when the
// answer can still change, then settle and report.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::path::Path;

use crate::core::vault::Vault;

use super::super::common::exact_name;
use super::super::directory::{resolved_directory, sealed_record};
use super::super::eligibility::lifecycle_blockers;
use super::super::quarantine::enforce_provider_effect;
use super::super::state::{
    context_block, item_revision, lifecycle_state, live_item_exists, request_item_id,
    update_request,
};
use super::super::wire::{request_payload, run_weles, wire_request, WIRE_VERSION};
use super::super::{ACCOUNT_PROVIDER, IDENTITY_PROVIDER, STATE_MANAGED, STATE_QUARANTINED, STATE_UNMANAGED};
use super::commit::{settle, Record};
use super::snapshot::emit;

// One poll of the exact Weles action log, persisted exactly like a manual
// `credential status` run.
pub(in crate::credential) fn status_once(vault_path: &Path, args: &[String]) -> Result<Value> {
    let credential_id = args.first().context("usage: credential status <item-id>")?;
    exact_name("credential item id", credential_id, "200".parse()?)?;
    let request_item = request_item_id(credential_id);
    let mut vault = Vault::open(vault_path.to_path_buf())?;
    let sealed_only =
        !live_item_exists(&vault, credential_id) && sealed_record(&vault, credential_id)?.is_some();
    let mut request = match vault.get_item(&request_item).and_then(request_payload) {
        Ok(request) => request,
        Err(_) if live_item_exists(&vault, credential_id) => {
            let state = lifecycle_state(&vault, credential_id)?;
            let directory = resolved_directory(&vault, credential_id)?;
            let blockers =
                lifecycle_blockers(&vault, credential_id, None, directory.as_ref(), None);
            return Ok(json!({
                "ok": state == STATE_MANAGED,
                "status": state,
                "lifecycle_state": state,
                "credential": credential_id,
                "revision": item_revision(&vault, credential_id),
                "directory": directory,
                "receipt": context_block(&vault, credential_id, "receipt"),
                "quarantine": context_block(&vault, credential_id, "quarantine"),
                "externally_verified": false,
                "lifecycle_eligible": blockers.is_empty(),
                "lifecycle_blockers": blockers,
            }));
        }
        // A sealed contract with no item yet is the normal state before the
        // first adopt or acquire, and it is worth reporting as such.
        Err(_) if sealed_only => {
            let directory = resolved_directory(&vault, credential_id)?;
            let blockers =
                lifecycle_blockers(&vault, credential_id, None, directory.as_ref(), None);
            return Ok(json!({
                "ok": false,
                "status": STATE_UNMANAGED,
                "lifecycle_state": STATE_UNMANAGED,
                "credential": credential_id,
                "revision": Value::Null,
                "directory": directory,
                "externally_verified": false,
                "lifecycle_eligible": blockers.is_empty(),
                "lifecycle_blockers": blockers,
            }));
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("no credential or operation request exists for {credential_id}")
            });
        }
    };
    // Clean cutover: a record written by an older wire version carries no
    // sealed directory identity, so it can never be polled or completed as one.
    if request.get("version").and_then(Value::as_str) != Some(WIRE_VERSION) {
        bail!("{credential_id} has a credential operation record from an unsupported wire version; expected {WIRE_VERSION}");
    }
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .context("credential operation has no operation")?
        .to_string();
    let request_id = request
        .get("request_id")
        .and_then(Value::as_str)
        .context("credential operation has no request id")?
        .to_string();
    let field = request
        .get("field")
        .and_then(Value::as_str)
        .context("credential operation has no exact field")?
        .to_string();
    let writer = request
        .get("consumer")
        .and_then(Value::as_str)
        .context("credential operation has no exact writer")?
        .to_string();
    let provider = request
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let directory = request
        .get("directory")
        .filter(|value| !value.is_null())
        .cloned();
    let account = match provider.as_str() {
        ACCOUNT_PROVIDER => request
            .get("account_email")
            .and_then(Value::as_str)
            .map(str::to_string),
        IDENTITY_PROVIDER => directory
            .as_ref()
            .and_then(|block| block.get("account_upn"))
            .and_then(Value::as_str)
            .map(str::to_string),
        _ => None,
    };
    let mut current_status = request
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    if matches!(
        current_status.as_str(),
        "pending" | "operation_queued" | "needs_human_approval"
    ) {
        let action_log_id = request
            .get("weles")
            .and_then(|value| value.get("action_log_id"))
            .and_then(Value::as_str)
            .context("pending credential operation has no Weles action log id")?
            .to_string();
        let poll_request = wire_request(&request, "status", Some(action_log_id.as_str()), None)?;
        let remote = run_weles(&poll_request)?;
        let remote_status = remote
            .get("status")
            .and_then(Value::as_str)
            .context("Weles status response is missing status")?;
        current_status = if remote_status == "operation_queued" {
            "pending".to_string()
        } else {
            remote_status.to_string()
        };
        // An unknown provider effect freezes the item before anything is
        // committed, so the persisted state is the frozen one.
        if enforce_provider_effect(vault_path, credential_id, &operation, &request_id, &remote)? {
            current_status = STATE_QUARANTINED.to_string();
        }
        update_request(
            vault_path,
            &request_item,
            &request,
            &current_status,
            Some(&remote),
        )?;
        vault = Vault::open(vault_path.to_path_buf())?;
        request = vault.get_item(&request_item).and_then(request_payload)?;
    }

    let receipt = request
        .get("weles")
        .and_then(|weles| weles.get("receipt"))
        .filter(|receipt| !receipt.is_null())
        .cloned();
    let record = Record {
        vault_path,
        credential_id,
        request_item: &request_item,
        operation: &operation,
        request_id: &request_id,
        field: &field,
        writer: &writer,
        provider: &provider,
        directory,
        account,
        receipt,
    };
    let (confirmed, current_status) = settle(&record, &mut vault, &mut request, current_status)?;
    emit(&record, &request, confirmed, &current_status)
}
