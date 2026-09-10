// What the vault already says before anything is submitted: whether this
// credential is managed, whether an earlier request of the same operation is
// still open, and which revision the provider will be answering against.

use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::path::Path;

use crate::core::inbox;
use crate::core::vault::Vault;

use super::super::adopt::{adopt_shape_of, AdoptShape};
use super::super::quarantine::enforce_retry_barrier;
use super::super::state::{item_revision, lifecycle_state, live_item_exists, request_item_id};
use super::super::wire::{request_payload, WIRE_VERSION};
use super::super::STATE_MANAGED;
use super::inputs::Submission;

/// Either the answer this operation already has, or what it still needs.
pub(super) enum Preflight {
    /// The vault answers without calling the provider at all.
    Answered(Value),
    Proceed(Proceed),
}

pub(super) struct Proceed {
    pub(super) resumable_request: Option<Value>,
    pub(super) adopt_shape: Option<AdoptShape>,
    pub(super) baseline_revision: u64,
}

pub(super) fn preflight(vault_path: &Path, submission: &Submission<'_>) -> Result<Preflight> {
    let credential_id = submission.credential_id;
    let operation = submission.operation;
    let request_item = request_item_id(credential_id);
    let mut resumable_request: Option<Value> = None;
    let mut adopt_shape: Option<AdoptShape> = None;
    let mut baseline_revision = u64::MIN;
    if submission.dry_run {
        return Ok(Preflight::Proceed(Proceed {
            resumable_request,
            adopt_shape,
            baseline_revision,
        }));
    }

    let vault = Vault::open(vault_path.to_path_buf())?;
    let live = live_item_exists(&vault, credential_id);
    let managed = live && inbox::managed_by_weles(&vault, credential_id);
    let state = lifecycle_state(&vault, credential_id)?;
    match operation {
        "acquire" if managed => {
            return Ok(Preflight::Answered(json!({
                "ok": true,
                "status": "managed",
                "credential": credential_id,
                "revision": item_revision(&vault, credential_id),
            })));
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
            if live && inbox::written_by(&vault, credential_id).as_deref() != Some(submission.consumer)
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
            bail!("{credential_id} is {state}, not managed; finish the adoption before {operation}");
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
                == Some(submission.provider)
                && existing.get("consumer").and_then(Value::as_str) == Some(submission.consumer)
                && existing.get("purpose").and_then(Value::as_str)
                    == Some(submission.purpose.as_str())
                && existing.get("account_email").and_then(Value::as_str)
                    == submission.account.as_deref()
                && existing.get("directory").filter(|value| !value.is_null())
                    == submission.wire_block.as_ref();
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
                || existing.get("status").and_then(Value::as_str) == Some("needs_human_approval")
            {
                return Ok(Preflight::Answered(json!({
                    "ok": true,
                    "status": existing.get("status"),
                    "operation": operation,
                    "credential": credential_id,
                    "request_id": existing.get("request_id"),
                    "weles": existing.get("weles"),
                })));
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

    Ok(Preflight::Proceed(Proceed {
        resumable_request,
        adopt_shape,
        baseline_revision,
    }))
}
