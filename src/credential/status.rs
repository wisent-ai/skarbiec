// status: one poll of the exact Weles action log, persisted exactly like a
// manual run, and the `--follow` watch that ends on a terminal state.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::core::inbox;
use crate::core::vault::Vault;
use crate::runtime::audit;

use super::adopt::{adopt_shape_of, trash_adopted_item, AdoptShape};
use super::common::{exact_name, now_iso};
use super::directory::{resolved_directory, sealed_record};
use super::eligibility::lifecycle_blockers;
use super::quarantine::{enforce_provider_effect, quarantine_credential};
use super::receipt::receipt_matches;
use super::state::{
    context_block, item_matches_request, item_revision, lifecycle_state, live_item_exists,
    pending_matches_request, request_item_id, store_context, update_request,
};
use super::wire::{request_payload, run_weles, wire_request, DIAGNOSTIC_KEYS, WIRE_VERSION};
use super::{
    ACCOUNT_PROVIDER, IDENTITY_PROVIDER, STATE_MANAGED, STATE_QUARANTINED, STATE_UNMANAGED,
    TERMINAL_STATUSES,
};

// One poll of the exact Weles action log, persisted exactly like a manual
// `credential status` run.
pub(super) fn status_once(vault_path: &Path, args: &[String]) -> Result<Value> {
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
            let blockers = lifecycle_blockers(&vault, credential_id, None, directory.as_ref());
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
            let blockers = lifecycle_blockers(&vault, credential_id, None, directory.as_ref());
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
    let mut confirmed = current_status == "completed";
    if current_status == "operation_completed" {
        // A completed directory operation without a receipt cannot be
        // attributed to this exact principal: freeze instead of committing.
        let receipt_valid = receipt.as_ref().is_some_and(|receipt| {
            receipt_matches(receipt, directory.as_ref(), &operation, &request_id)
        });
        if provider == IDENTITY_PROVIDER && !receipt_valid {
            quarantine_credential(
                vault_path,
                credential_id,
                &operation,
                &request_id,
                Some("unknown"),
                request
                    .get("weles")
                    .and_then(|weles| weles.get("rollback_status"))
                    .and_then(Value::as_str),
            )?;
            update_request(vault_path, &request_item, &request, STATE_QUARANTINED, None)?;
            current_status = STATE_QUARANTINED.to_string();
        } else {
            confirmed = match operation.as_str() {
                "acquire" => {
                    inbox::managed_by_weles(&vault, credential_id)
                        && inbox::written_by(&vault, credential_id).as_deref()
                            == Some(writer.as_str())
                        && item_matches_request(
                            &vault,
                            credential_id,
                            &request_id,
                            &operation,
                            account.as_deref(),
                        )
                }
                // adopt commits the operator's own value: the staged candidate
                // is activated, or the item this adopt created is promoted out
                // of the adopting state.
                "adopt" => match adopt_shape_of(&request)? {
                    AdoptShape::Staged => {
                        if !pending_matches_request(
                            &vault,
                            credential_id,
                            &request_id,
                            &field,
                            &writer,
                        ) {
                            false
                        } else {
                            vault.activate_staged_revision(
                                credential_id,
                                &request_id,
                                &field,
                                &writer,
                            )?;
                            true
                        }
                    }
                    AdoptShape::Created => {
                        inbox::managed_by_weles(&vault, credential_id)
                            && inbox::written_by(&vault, credential_id).as_deref()
                                == Some(writer.as_str())
                            && item_matches_request(
                                &vault,
                                credential_id,
                                &request_id,
                                &operation,
                                account.as_deref(),
                            )
                    }
                },
                // reset commits the same way as rotate: the staged provider value
                // becomes current only after Weles reports the change landed.
                "rotate" | "reset" => {
                    if !pending_matches_request(&vault, credential_id, &request_id, &field, &writer)
                    {
                        false
                    } else {
                        vault.activate_staged_revision(
                            credential_id,
                            &request_id,
                            &field,
                            &writer,
                        )?;
                        true
                    }
                }
                "verify" => {
                    let same = vault
                        .doc()
                        .get("items")
                        .and_then(|items| items.get(credential_id))
                        .and_then(|item| item.get("pending"))
                        .and_then(|pending| pending.get("same_as_current"))
                        .and_then(Value::as_bool)
                        == Some(true);
                    if !same
                        || !pending_matches_request(
                            &vault,
                            credential_id,
                            &request_id,
                            &field,
                            &writer,
                        )
                    {
                        false
                    } else {
                        vault.discard_staged_revision(
                            credential_id,
                            &request_id,
                            &field,
                            &writer,
                        )?;
                        true
                    }
                }
                "remove" => {
                    vault.trash_managed_item(credential_id, "weles", &writer)?;
                    true
                }
                _ => false,
            };
            if confirmed {
                // The receipt is persisted with the revision it proves, so
                // `credential status` answers "was exactly this principal
                // rotated" without reading a mailbox.
                if live_item_exists(&vault, credential_id) {
                    store_context(
                        &mut vault,
                        credential_id,
                        &[
                            ("receipt", receipt.clone().unwrap_or(Value::Null)),
                            (
                                "lifecycle",
                                json!({
                                    "state": STATE_MANAGED,
                                    "operation": operation,
                                    "request_id": request_id,
                                    "updated_at": now_iso(),
                                }),
                            ),
                        ],
                    )?;
                }
                update_request(vault_path, &request_item, &request, "completed", None)?;
                audit::append_sync(
                    "credential-operation-completed",
                    &json!({
                        "credential": credential_id,
                        "operation": operation,
                        "request_id": request_id,
                        "field": field,
                        "evidence_digest": receipt
                            .as_ref()
                            .and_then(|receipt| receipt.get("evidence_digest")),
                    }),
                )?;
                current_status = "completed".to_string();
                vault = Vault::open(vault_path.to_path_buf())?;
                request = vault.get_item(&request_item).and_then(request_payload)?;
            } else {
                update_request(vault_path, &request_item, &request, "inconsistent", None)?;
                current_status = "inconsistent".to_string();
            }
        }
    } else if matches!(current_status.as_str(), "operation_failed" | "failed") {
        // "failed" is the legacy spelling recorded by submit/resume paths that
        // never reached Weles; records carrying it predate the unified
        // "operation_failed" vocabulary and settle through the same rollback.
        let staged = pending_matches_request(&vault, credential_id, &request_id, &field, &writer);
        if staged {
            vault.discard_staged_revision(credential_id, &request_id, &field, &writer)?;
            audit::append_sync(
                "credential-operation-rollback",
                &json!({
                    "credential": credential_id,
                    "operation": operation,
                    "request_id": request_id,
                    "field": field,
                }),
            )?;
        }
        if operation == "adopt" {
            match adopt_shape_of(&request)? {
                // The item this adopt created goes away entirely; a
                // pre-existing item can never reach this branch.
                AdoptShape::Created => {
                    trash_adopted_item(&mut vault, credential_id, &request_id, &writer)?;
                }
                AdoptShape::Staged => {
                    if live_item_exists(&vault, credential_id) {
                        store_context(
                            &mut vault,
                            credential_id,
                            &[(
                                "lifecycle",
                                json!({
                                    "state": STATE_UNMANAGED,
                                    "operation": operation,
                                    "request_id": request_id,
                                    "updated_at": now_iso(),
                                }),
                            )],
                        )?;
                    }
                }
            }
        }
    }
    // Quarantine and commit paths write through their own vault handles, so
    // the emitted snapshot is read from a fresh one.
    vault = Vault::open(vault_path.to_path_buf())?;
    let lifecycle = lifecycle_state(&vault, credential_id)?;
    // Eligibility answers for the item as it stands now: the record's sealed
    // block when it carries one, otherwise whatever the item itself resolves
    // to. A contract that resolves to nothing is no contract to run against.
    let sealed = directory
        .clone()
        .or_else(|| resolved_directory(&vault, credential_id).ok().flatten());
    let blockers = lifecycle_blockers(
        &vault,
        credential_id,
        Some(provider.as_str()).filter(|provider| !provider.is_empty()),
        sealed.as_ref(),
    );
    let mut emitted = json!({
        "ok": confirmed,
        "status": current_status,
        "lifecycle_state": lifecycle,
        "operation": operation,
        "credential": credential_id,
        "request_id": request.get("request_id"),
        "weles": request.get("weles"),
        "created_at": request.get("created_at"),
        "updated_at": request.get("updated_at"),
        "externally_verified": confirmed && lifecycle == STATE_MANAGED,
        "revision": item_revision(&vault, credential_id),
        "directory": directory,
        "receipt": context_block(&vault, credential_id, "receipt").or(receipt),
        "quarantine": context_block(&vault, credential_id, "quarantine"),
        "lifecycle_eligible": blockers.is_empty(),
        "lifecycle_blockers": blockers,
    });
    if let (Some(object), Some(weles)) = (emitted.as_object_mut(), request.get("weles")) {
        for key in DIAGNOSTIC_KEYS.iter().copied() {
            if let Some(found) = weles.get(key).filter(|value| !value.is_null()) {
                object.insert(key.to_string(), found.clone());
            }
        }
    }
    Ok(emitted)
}

pub(super) fn status(
    vault_path: &Path,
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<Value> {
    let allowed = ["follow", "local"];
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("usage: credential status <item-id> [--follow] [--local]");
    }
    if !flags.get("follow").is_some_and(|value| value == "true") {
        return status_once(vault_path, args);
    }
    let interval = Duration::from_secs("5".parse()?);
    let limit = Duration::from_secs("1800".parse()?);
    let started = Instant::now();
    loop {
        let snapshot = status_once(vault_path, args)?;
        let current = snapshot
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        // `pending` is the only state another poll can advance. Everything
        // else ends the watch: the contract terminal states, and local states
        // such as managed, unmanaged, adopting, quarantined, or failed that
        // carry no pollable action log. `follow_settled` says which happened.
        if current != "pending" {
            let mut settled = snapshot;
            settled
                .as_object_mut()
                .context("credential status is not an object")?
                .insert(
                    "follow_settled".to_string(),
                    Value::Bool(TERMINAL_STATUSES.contains(&current.as_str())),
                );
            return Ok(settled);
        }
        if started.elapsed().saturating_add(interval) > limit {
            let mut timed_out = snapshot;
            timed_out
                .as_object_mut()
                .context("credential status is not an object")?
                .insert("follow_timed_out".to_string(), Value::Bool(true));
            return Ok(timed_out);
        }
        std::thread::sleep(interval);
    }
}
