// What a finished provider operation does to the vault: commit the staged
// revision the operation promised, or roll it back and say so.

use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;

use crate::core::inbox;
use crate::core::vault::Vault;
use crate::runtime::audit;

use super::super::adopt::{adopt_shape_of, trash_adopted_item, AdoptShape};
use super::super::common::now_iso;
use super::super::quarantine::quarantine_credential;
use super::super::receipt::receipt_matches;
use super::super::state::{
    item_matches_request, live_item_exists, pending_matches_request, store_context, update_request,
};
use super::super::wire::request_payload;
use super::super::{IDENTITY_PROVIDER, STATE_MANAGED, STATE_QUARANTINED, STATE_UNMANAGED};
use super::subscription::named_subscription_present;

/// Everything one settled operation is decided against, gathered once.
pub(super) struct Record<'a> {
    pub(super) vault_path: &'a Path,
    pub(super) credential_id: &'a str,
    pub(super) request_item: &'a str,
    pub(super) operation: &'a str,
    pub(super) request_id: &'a str,
    pub(super) field: &'a str,
    pub(super) writer: &'a str,
    pub(super) provider: &'a str,
    pub(super) directory: Option<Value>,
    pub(super) account: Option<String>,
    pub(super) receipt: Option<Value>,
}

/// Commit or roll back what the provider reported, and say which happened.
///
/// The vault handle and the record are reopened here exactly where the
/// single-function version reopened them, so a caller reads the same state
/// after this returns as it did before the split.
pub(super) fn settle(
    record: &Record<'_>,
    mut vault: &mut Vault,
    request: &mut Value,
    current_status: String,
) -> Result<(bool, String)> {
    let vault_path = record.vault_path;
    let credential_id = record.credential_id;
    let request_item = record.request_item;
    let operation = record.operation.to_string();
    let request_id = record.request_id.to_string();
    let field = record.field.to_string();
    let writer = record.writer.to_string();
    let provider = record.provider.to_string();
    let directory = record.directory.clone();
    let account = record.account.clone();
    let mut current_status = current_status;
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
                "reauth" => named_subscription_present(&vault, credential_id),
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
                *vault = Vault::open(vault_path.to_path_buf())?;
                *request = vault.get_item(&request_item).and_then(request_payload)?;
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
    Ok((confirmed, current_status))
}
