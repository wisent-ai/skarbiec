// The answer a caller reads: the item as it stands now, what the provider
// said, and whether it is eligible for another operation.

use anyhow::Result;
use serde_json::{json, Value};

use crate::core::vault::Vault;

use super::super::directory::resolved_directory;
use super::super::eligibility::lifecycle_blockers;
use super::super::state::{context_block, item_revision, lifecycle_state};
use super::super::wire::DIAGNOSTIC_KEYS;
use super::super::STATE_MANAGED;
use super::commit::Record;

/// The snapshot a caller reads, taken from a vault handle opened here.
///
/// Quarantine and commit paths write through their own handles, so the state
/// this reports is read after they are done, never from a stale one.
pub(super) fn emit(
    record: &Record<'_>,
    request: &Value,
    confirmed: bool,
    current_status: &str,
) -> Result<Value> {
    let vault_path = record.vault_path;
    let credential_id = record.credential_id;
    let operation = record.operation.to_string();
    let provider = record.provider.to_string();
    let directory = record.directory.clone();
    let receipt = record.receipt.clone();
    let vault = Vault::open(vault_path.to_path_buf())?;
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
        Some(operation.as_str()).filter(|operation| !operation.is_empty()),
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
