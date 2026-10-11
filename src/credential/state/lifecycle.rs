// Which lifecycle state an item is in, and the refusal a quarantined one
// answers with. Quarantine is read from the record and from the item's own
// tag: either one is enough to stop an operation.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::core::inbox;
use crate::core::vault::Vault;

use super::super::wire::request_payload;
use super::super::{
    ITEM_STATES, QUARANTINE_CONFIRMATION, QUARANTINE_TAG, STATE_MANAGED, STATE_QUARANTINED,
    STATE_UNMANAGED,
};
use super::records::{context_block_checked, live_item_exists, request_item_id};

pub(in crate::credential) fn quarantine_tagged(vault: &Vault, id: &str) -> bool {
    vault
        .doc()
        .get("items")
        .and_then(|items| items.get(id))
        .and_then(|item| item.get("tags"))
        .and_then(Value::as_array)
        .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(QUARANTINE_TAG)))
}

/// Whether the credential's request record says quarantined. Only an absent
/// request item reads as not quarantined; one that cannot be decrypted or
/// parsed is an error naming it, because read as "not quarantined" it let a
/// lifecycle operation start on a credential nobody can vouch for.
pub(in crate::credential) fn record_quarantined(
    vault: &Vault,
    credential_id: &str,
) -> Result<bool> {
    let request_item = request_item_id(credential_id);
    if !live_item_exists(vault, &request_item) {
        return Ok(false);
    }
    let request = vault.get_item(&request_item).and_then(request_payload).with_context(|| {
        format!("{credential_id}: request item {request_item} cannot be read, so its quarantine cannot be checked")
    })?;
    Ok(request.get("status").and_then(Value::as_str) == Some(STATE_QUARANTINED))
}

/// Whether the credential is quarantined, or the error that keeps it from
/// being known; `lifecycle_state`, `refuse_quarantined` and `credential status`
/// name that error.
pub(in crate::credential) fn quarantine_state(vault: &Vault, credential_id: &str) -> Result<bool> {
    if record_quarantined(vault, credential_id)? || quarantine_tagged(vault, credential_id) {
        return Ok(true);
    }
    Ok(context_block_checked(vault, credential_id, "quarantine")?
        .is_some_and(|block| block.get("state").and_then(Value::as_str) == Some(STATE_QUARANTINED)))
}

/// The same answer for callers that can only refuse or proceed: a quarantine
/// that cannot be checked counts as one, so a managed write never lands on a
/// credential whose request record is unreadable.
pub(in crate::credential) fn quarantine_active(vault: &Vault, credential_id: &str) -> bool {
    match quarantine_state(vault, credential_id) {
        Ok(quarantined) => quarantined,
        Err(error) => {
            eprintln!("{error:#}; treated as quarantined");
            true
        }
    }
}

// unmanaged, managed, adopting, or quarantined. An unknown stored state is a
// refusal, never a guess.
pub(crate) fn lifecycle_state(vault: &Vault, credential_id: &str) -> Result<String> {
    if quarantine_state(vault, credential_id)? {
        return Ok(STATE_QUARANTINED.to_string());
    }
    if let Some(state) = context_block_checked(vault, credential_id, "lifecycle")?
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
    if quarantine_state(vault, credential_id)? {
        bail!(
            "{credential_id} is quarantined: nobody knows which password the provider accepts, so {operation} is refused. Resolve it with credential resolve-quarantine {credential_id} --confirm '{QUARANTINE_CONFIRMATION}'"
        );
    }
    Ok(())
}
