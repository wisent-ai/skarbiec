// Which revision an acquisition may read while an adopt is in flight, and
// when the staged candidate has to stay hidden.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::core::vault::Vault;
use crate::core::{crypto, inbox, schema};

use super::super::state::{context_block, pending_matches_request, request_item_id};
use super::super::wire::{request_payload, WIRE_VERSION};
use super::super::STATE_ADOPTING;
use super::ManagedRead;

pub(in crate::credential) fn staged_field_value(
    vault: &Vault,
    credential_id: &str,
    field: &str,
) -> Result<Option<Value>> {
    let Some(pending) = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(credential_id))
        .and_then(|item| item.get("pending"))
        .cloned()
    else {
        return Ok(None);
    };
    let kind = pending
        .get("kind")
        .and_then(Value::as_str)
        .context("staged revision has no kind")?;
    let cipher = pending
        .get("ciphertext")
        .and_then(Value::as_str)
        .context("staged revision has no ciphertext")?;
    let plain = crypto::decrypt(cipher)?;
    let payload: Value =
        serde_json::from_str(&plain).context("decrypted staged revision is not JSON")?;
    schema::validate_payload(&payload, kind)?;
    Ok(Some(schema::field(&payload, field)?.clone()))
}

// What an acquisition read may return. The adopt candidate is readable only by
// the exact verification path: an active adopt for this item, that request id,
// that field, and that presenting consumer. Outside that window a candidate
// sitting as the current revision is unreadable.
pub(crate) fn managed_read(
    vault: &Vault,
    credential_id: &str,
    field: &str,
    consumer: &str,
) -> Result<ManagedRead> {
    let lifecycle = context_block(vault, credential_id, "lifecycle").unwrap_or_default();
    let adopting = lifecycle.get("state").and_then(Value::as_str) == Some(STATE_ADOPTING);
    let candidate_is_current =
        lifecycle.get("candidate").and_then(Value::as_str) == Some("current");
    let record = vault
        .get_item(&request_item_id(credential_id))
        .and_then(request_payload)
        .ok()
        .filter(|request| {
            request.get("version").and_then(Value::as_str) == Some(WIRE_VERSION)
                && request.get("operation").and_then(Value::as_str) == Some("adopt")
                && request.get("credential_id").and_then(Value::as_str) == Some(credential_id)
                && request.get("field").and_then(Value::as_str) == Some(field)
                && request.get("consumer").and_then(Value::as_str) == Some(consumer)
                && matches!(
                    request.get("status").and_then(Value::as_str),
                    Some("submitting" | "pending" | "needs_human_approval")
                )
        });
    if let Some(record) = record.as_ref() {
        let request_id = record
            .get("request_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if pending_matches_request(vault, credential_id, request_id, field, consumer) {
            if let Some(value) = staged_field_value(vault, credential_id, field)? {
                return Ok(ManagedRead::Staged(value));
            }
        }
        let created_candidate = adopting
            && candidate_is_current
            && lifecycle.get("request_id").and_then(Value::as_str) == Some(request_id)
            && inbox::written_by(vault, credential_id).as_deref() == Some(consumer);
        if created_candidate {
            return Ok(ManagedRead::Current);
        }
    }
    if adopting && candidate_is_current {
        return Ok(ManagedRead::Refused);
    }
    Ok(ManagedRead::Current)
}

// True when this caller may not see the item's current value because an
// unconfirmed adopt candidate is sitting in it. A read that cannot be judged
// is hidden too.
pub(crate) fn candidate_hidden(
    vault: &Vault,
    credential_id: &str,
    field: &str,
    consumer: &str,
) -> bool {
    !matches!(
        managed_read(vault, credential_id, field, consumer),
        Ok(ManagedRead::Current) | Ok(ManagedRead::Staged(_))
    )
}
