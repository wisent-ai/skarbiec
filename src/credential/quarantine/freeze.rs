// Freezing an item when nobody can say which password the provider accepts,
// and refusing the retry that would run against a value we no longer know.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::path::Path;

use crate::core::vault::Vault;
use crate::runtime::audit;

use super::super::common::now_iso;
use super::super::state::{live_item_exists, store_context};
use super::super::{QUARANTINE_TAG, STATE_QUARANTINED};

// The freeze marker lives in the plaintext envelope: it can be set while a
// staged candidate exists, which is exactly when we must not re-encrypt the
// payload and lose that candidate. That is why this writes the envelope
// directly instead of going through `set_item_with_writer`.
//
// It does go through the tag registry, though. This path used to be exempt on
// the grounds that it writes one crate constant rather than operator input,
// which was true and still left the product minting a namespace its own
// registry did not contain. `lifecycle:quarantined` is registered now, so the
// exemption bought nothing and is gone: the check is cheap, it is pure string
// comparison over the envelope, and running it here means a future edit to
// `QUARANTINE_TAG` cannot introduce an unregistered namespace unnoticed. The
// same rule applies as everywhere else -- only what this write introduces is
// judged, so clearing the marker is never refused.
pub(in crate::credential) fn mark_quarantine_tag(
    vault: &mut Vault,
    id: &str,
    frozen: bool,
) -> Result<()> {
    let entry = vault
        .doc_mut()
        .get_mut("items")
        .and_then(|items| items.get_mut(id))
        .and_then(Value::as_object_mut)
        .with_context(|| format!("no item: {id}"))?;
    let carried: Vec<Value> = entry
        .get("tags")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let tagged = carried
        .iter()
        .any(|tag| tag.as_str() == Some(QUARANTINE_TAG));
    if frozen == tagged {
        return Ok(());
    }
    let mut written = carried.clone();
    if frozen {
        written.push(Value::String(QUARANTINE_TAG.to_string()));
    } else {
        written.retain(|tag| tag.as_str() != Some(QUARANTINE_TAG));
    }
    crate::core::schema::ensure_registered_tags(&carried, &written)?;
    entry.insert("tags".to_string(), Value::Array(written));
    vault.save()
}

// We do not know which password the provider accepts. Freeze the item and the
// operation record; the staged candidate, if any, is kept because it may be
// the value that is now live.
pub(in crate::credential) fn quarantine_credential(
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
pub(in crate::credential) fn enforce_retry_barrier(
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

// Freezes the item when nobody can say which password the provider accepts: an
// unknown effect, a rollback that failed or was never proven, or a failed
// operation that changed the password without a confirmed rollback. The last
// case matters most: the provider may hold exactly the value we staged, so the
// staged candidate must survive instead of being rolled back away.
pub(in crate::credential) fn enforce_provider_effect(
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
