// Quarantine: freezing an item when nobody can say which password the provider
// accepts, keeping the staged candidate that may now be live, and the operator
// path back out.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use crate::access::tokens;
use crate::core::vault::Vault;
use crate::runtime::audit;

use super::common::{acquire_credential_operation_lock, client_identity, exact_name, now_iso};
use super::state::{
    context_block, live_item_exists, pending_matches_request, quarantine_active, request_item_id,
    store_context, update_request,
};
use super::wire::request_payload;
use super::{QUARANTINE_CONFIRMATION, QUARANTINE_TAG, STATE_QUARANTINED, STATE_UNMANAGED};

// The freeze marker lives in the plaintext envelope: it can be set while a
// staged candidate exists, which is exactly when we must not re-encrypt the
// payload and lose that candidate.
//
// It also does not pass the tag registry, because it is not operator input:
// the only value written here is one crate constant, set and cleared by the
// quarantine lifecycle alone, the same way the sealed directory identity and
// the provider receipt are lifecycle-owned and never written through an item
// API. Worth stating plainly, though: `lifecycle:quarantined` is namespaced
// and is not one of the registered namespaces, so it is a tag this binary
// mints that the registry does not list. Nothing breaks -- a write that keeps
// it is preserving, not introducing -- but re-adding it by hand after a retag
// dropped it would be refused.
pub(super) fn mark_quarantine_tag(vault: &mut Vault, id: &str, frozen: bool) -> Result<()> {
    let entry = vault
        .doc_mut()
        .get_mut("items")
        .and_then(|items| items.get_mut(id))
        .and_then(Value::as_object_mut)
        .with_context(|| format!("no item: {id}"))?;
    let mut tags: Vec<Value> = entry
        .get("tags")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let tagged = tags.iter().any(|tag| tag.as_str() == Some(QUARANTINE_TAG));
    if frozen == tagged {
        return Ok(());
    }
    if frozen {
        tags.push(Value::String(QUARANTINE_TAG.to_string()));
    } else {
        tags.retain(|tag| tag.as_str() != Some(QUARANTINE_TAG));
    }
    entry.insert("tags".to_string(), Value::Array(tags));
    vault.save()
}

// We do not know which password the provider accepts. Freeze the item and the
// operation record; the staged candidate, if any, is kept because it may be
// the value that is now live.
pub(super) fn quarantine_credential(
    vault_path: &Path,
    credential_id: &str,
    operation: &str,
    request_id: &str,
    effect: Option<&str>,
    rollback: Option<&str>,
) -> Result<()> {
    let stamp = now_iso();
    let quarantine = json!({
        "state": STATE_QUARANTINED,
        "operation": operation,
        "request_id": request_id,
        "provider_effect": effect,
        "rollback_status": rollback,
        "quarantined_at": stamp,
    });
    let mut vault = Vault::open(vault_path.to_path_buf())?;
    if live_item_exists(&vault, credential_id) {
        mark_quarantine_tag(&mut vault, credential_id, true)?;
        let staged = vault
            .doc()
            .get("items")
            .and_then(|items| items.get(credential_id))
            .and_then(|item| item.get("pending"))
            .is_some();
        if !staged {
            store_context(
                &mut vault,
                credential_id,
                &[
                    ("quarantine", quarantine.clone()),
                    (
                        "lifecycle",
                        json!({
                            "state": STATE_QUARANTINED,
                            "operation": operation,
                            "request_id": request_id,
                            "updated_at": stamp,
                        }),
                    ),
                ],
            )?;
        }
    }
    audit::append_sync(
        "credential-operation-quarantined",
        &json!({
            "credential": credential_id,
            "operation": operation,
            "request_id": request_id,
            "provider_effect": effect,
            "rollback_status": rollback,
        }),
    )
}

// A provider-side change or an unknown effect must never be retried blindly:
// the same operation would run against a password we no longer know.
pub(super) fn enforce_retry_barrier(
    existing: &Value,
    credential_id: &str,
    operation: &str,
) -> Result<()> {
    let weles = existing.get("weles");
    let effect = weles
        .and_then(|weles| weles.get("provider_effect"))
        .and_then(Value::as_str);
    let rollback = weles
        .and_then(|weles| weles.get("rollback_status"))
        .and_then(Value::as_str);
    let status = existing
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let previous = existing
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    // A completed operation, or one an operator settled explicitly, is not a
    // provider state anybody still has to guess at.
    if matches!(status, "completed" | "quarantine_resolved") {
        return Ok(());
    }
    if effect == Some("unknown") {
        bail!(
            "{credential_id} is quarantined: the last {previous} left the provider password in an unknown state, so {operation} is refused until credential resolve-quarantine settles it"
        );
    }
    if effect == Some("changed") && rollback != Some("completed") && operation != "verify" {
        bail!(
            "PROVIDER_EFFECT_CHANGED_RETRY_BLOCKED: the last {previous} of {credential_id} changed the provider password without a confirmed local commit or rollback; run credential verify {credential_id} before {operation}"
        );
    }
    Ok(())
}

pub(super) fn resolve_quarantine(
    vault_path: &Path,
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<Value> {
    let allowed = ["confirm", "staged", "as", "token-file", "local"];
    let usage = format!(
        "usage: credential resolve-quarantine <item-id> --confirm '{QUARANTINE_CONFIRMATION}' [--staged keep|activate|discard] --as <consumer> --token-file <path>"
    );
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{usage}");
    }
    let credential_id = args.first().context(usage.clone())?;
    exact_name("credential item id", credential_id, "200".parse()?)?;
    if flags.get("confirm").map(String::as_str) != Some(QUARANTINE_CONFIRMATION) {
        bail!("{usage}");
    }
    let staged_decision = flags.get("staged").map(String::as_str).unwrap_or("keep");
    if !["keep", "activate", "discard"].contains(&staged_decision) {
        bail!("--staged must be keep, activate, or discard");
    }
    let _lock = acquire_credential_operation_lock(vault_path)?;
    let mut vault = Vault::open(vault_path.to_path_buf())?;
    if !quarantine_active(&vault, credential_id) {
        bail!("{credential_id} is not quarantined");
    }
    let (consumer, token) = client_identity(flags)?;
    // The item may not exist yet (a quarantined acquire), in which case the
    // operation record is the only resource an admin capability can name.
    let admin_target = if live_item_exists(&vault, credential_id) {
        credential_id.to_string()
    } else {
        request_item_id(credential_id)
    };
    if !tokens::token_allows_action(&vault, &consumer, &token, "admin", &admin_target)? {
        bail!("{consumer} holds no admin capability for {admin_target}");
    }
    let request_item = request_item_id(credential_id);
    let record = vault.get_item(&request_item).and_then(request_payload).ok();
    let request_id = record
        .as_ref()
        .and_then(|record| record.get("request_id"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let field = record
        .as_ref()
        .and_then(|record| record.get("field"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let writer = record
        .as_ref()
        .and_then(|record| record.get("consumer"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let staged = !request_id.is_empty()
        && pending_matches_request(&vault, credential_id, &request_id, &field, &writer);
    if staged {
        match staged_decision {
            "activate" => {
                vault.activate_staged_revision(credential_id, &request_id, &field, &writer)?;
            }
            "discard" => {
                vault.discard_staged_revision(credential_id, &request_id, &field, &writer)?;
            }
            _ => {}
        }
    } else if staged_decision != "keep" {
        bail!("{credential_id} has no staged revision belonging to the quarantined operation");
    }
    let resolved_at = now_iso();
    if live_item_exists(&vault, credential_id) {
        mark_quarantine_tag(&mut vault, credential_id, false)?;
        let has_staged = vault
            .doc()
            .get("items")
            .and_then(|items| items.get(credential_id))
            .and_then(|item| item.get("pending"))
            .is_some();
        if !has_staged {
            let previous = context_block(&vault, credential_id, "quarantine");
            store_context(
                &mut vault,
                credential_id,
                &[
                    (
                        "quarantine",
                        json!({
                            "state": "resolved",
                            "resolved_at": resolved_at,
                            "resolved_by": consumer,
                            "staged_decision": staged_decision,
                            "previous": previous,
                        }),
                    ),
                    (
                        // Knowing the password again is an explicit act: the
                        // item returns to unmanaged until adopt or verify
                        // proves the value.
                        "lifecycle",
                        json!({
                            "state": STATE_UNMANAGED,
                            "operation": "resolve-quarantine",
                            "request_id": request_id,
                            "updated_at": resolved_at,
                        }),
                    ),
                ],
            )?;
        }
    }
    if let Some(record) = record.as_ref() {
        update_request(
            vault_path,
            &request_item,
            record,
            "quarantine_resolved",
            None,
        )?;
    }
    audit::append_sync(
        "credential-quarantine-resolved",
        &json!({
            "credential": credential_id,
            "request_id": request_id,
            "resolved_by": consumer,
            "staged_decision": staged_decision,
        }),
    )?;
    Ok(json!({
        "ok": true,
        "status": STATE_UNMANAGED,
        "credential": credential_id,
        "staged_decision": staged_decision,
        "resolved_at": resolved_at,
    }))
}

// Freezes the item when nobody can say which password the provider accepts: an
// unknown effect, a rollback that failed or was never proven, or a failed
// operation that changed the password without a confirmed rollback. The last
// case matters most: the provider may hold exactly the value we staged, so the
// staged candidate must survive instead of being rolled back away.
pub(super) fn enforce_provider_effect(
    vault_path: &Path,
    credential_id: &str,
    operation: &str,
    request_id: &str,
    response: &Value,
) -> Result<bool> {
    let effect = response.get("provider_effect").and_then(Value::as_str);
    let rollback = response.get("rollback_status").and_then(Value::as_str);
    let failed = matches!(
        response.get("status").and_then(Value::as_str),
        Some(
            "operation_failed"
                | "unsupported_operation"
                | "unsupported_secret"
                | "needs_configuration"
        )
    );
    let unresolved = effect == Some("unknown")
        || matches!(rollback, Some("failed" | "unknown"))
        || (failed && effect == Some("changed") && rollback != Some("completed"));
    if !unresolved {
        return Ok(false);
    }
    quarantine_credential(
        vault_path,
        credential_id,
        operation,
        request_id,
        effect,
        rollback,
    )?;
    Ok(true)
}
