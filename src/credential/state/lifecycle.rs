// Which lifecycle state an item is in, and the refusal a quarantined one
// answers with. Quarantine is read from the record and from the item's own
// tag: either one is enough to stop an operation.

use anyhow::{bail, Result};
use serde_json::Value;

use crate::core::inbox;
use crate::core::vault::Vault;

use super::super::wire::request_payload;
use super::super::{
    ITEM_STATES, QUARANTINE_CONFIRMATION, QUARANTINE_TAG, STATE_MANAGED, STATE_QUARANTINED,
    STATE_UNMANAGED,
};
use super::records::{context_block, live_item_exists, request_item_id};

pub(in crate::credential) fn quarantine_tagged(vault: &Vault, id: &str) -> bool {
    vault
        .doc()
        .get("items")
        .and_then(|items| items.get(id))
        .and_then(|item| item.get("tags"))
        .and_then(Value::as_array)
        .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(QUARANTINE_TAG)))
}

pub(in crate::credential) fn record_quarantined(vault: &Vault, credential_id: &str) -> bool {
    vault
        .get_item(&request_item_id(credential_id))
        .and_then(request_payload)
        .ok()
        .and_then(|request| {
            request
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .as_deref()
        == Some(STATE_QUARANTINED)
}

pub(in crate::credential) fn quarantine_active(vault: &Vault, credential_id: &str) -> bool {
    if record_quarantined(vault, credential_id) || quarantine_tagged(vault, credential_id) {
        return true;
    }
    context_block(vault, credential_id, "quarantine")
        .is_some_and(|block| block.get("state").and_then(Value::as_str) == Some(STATE_QUARANTINED))
}

// unmanaged, managed, adopting, or quarantined. An unknown stored state is a
// refusal, never a guess.
pub(crate) fn lifecycle_state(vault: &Vault, credential_id: &str) -> Result<String> {
    if quarantine_active(vault, credential_id) {
        return Ok(STATE_QUARANTINED.to_string());
    }
    if let Some(state) = context_block(vault, credential_id, "lifecycle")
        .as_ref()
        .and_then(|block| block.get("state"))
        .and_then(Value::as_str)
    {
        if !ITEM_STATES.contains(&state) {
            bail!("{credential_id} carries an unsupported lifecycle state: {state}");
        }
        return Ok(state.to_string());
    }
    if live_item_exists(vault, credential_id) && inbox::managed_by_weles(vault, credential_id) {
        return Ok(STATE_MANAGED.to_string());
    }
    Ok(STATE_UNMANAGED.to_string())
}

pub(in crate::credential) fn refuse_quarantined(
    vault: &Vault,
    credential_id: &str,
    operation: &str,
) -> Result<()> {
    if quarantine_active(vault, credential_id) {
        bail!(
            "{credential_id} is quarantined: nobody knows which password the provider accepts, so {operation} is refused. Resolve it with credential resolve-quarantine {credential_id} --confirm '{QUARANTINE_CONFIRMATION}'"
        );
    }
    Ok(())
}
