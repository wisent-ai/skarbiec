// The lifecycle state of one credential item, including whether it is frozen,
// the persisted operation record, and the authority that decides whether a
// managed write may land.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::path::Path;

use crate::core::vault::{ManagedWrite, Vault};
use crate::core::{inbox, schema};

use super::common::now_iso;
use super::wire::{request_envelope, request_payload, WIRE_VERSION};
use super::{
    ITEM_STATES, QUARANTINE_CONFIRMATION, QUARANTINE_TAG, REQUEST_KIND, REQUEST_WRITER,
    STATE_MANAGED, STATE_QUARANTINED, STATE_UNMANAGED,
};

pub(super) fn request_item_id(credential_id: &str) -> String {
    format!("operation:credential/{credential_id}")
}

// The sealed directory contract survives item absence: adopt and acquire copy
// it into the item they create, and the item keeps it from then on.
pub(crate) fn seal_item_id(credential_id: &str) -> String {
    format!("directory:credential/{credential_id}")
}

// Items the credential lifecycle owns end to end: operation records and sealed
// directory contracts. Both are written only by `save_request`, which writes
// them as `REQUEST_KIND` under a managed authority whose controller is
// `REQUEST_WRITER`; the vault refuses any later write that names a different
// authority, so that pair is the record's own declaration of who owns it and it
// cannot be forged through an item API. The id is not authoritative: it is a
// mutable human-chosen name, and deriving the write protection from how it
// happens to be spelled meant a rename silently removed the protection with
// nothing raised. An id this vault does not hold is not owned by anything --
// if something else takes the name first, the lifecycle's own managed write is
// the loud failure ("controlled by a different management authority").
// No item API may write, import, or accept a donation for one of these.
pub(crate) fn lifecycle_owned_item(vault: &Vault, id: &str) -> bool {
    let Some(item) = vault.doc().get("items").and_then(|items| items.get(id)) else {
        return false;
    };
    if item.get("kind").and_then(Value::as_str) != Some(REQUEST_KIND) {
        return false;
    }
    item.get("management").is_some_and(|management| {
        management.get("mode").and_then(Value::as_str) == Some("managed")
            && management.get("controller").and_then(Value::as_str) == Some(REQUEST_WRITER)
    })
}

pub(super) fn live_item_exists(vault: &Vault, id: &str) -> bool {
    vault
        .list(false)
        .iter()
        .any(|entry| entry.get("id").and_then(Value::as_str) == Some(id))
}

pub(super) fn save_request(vault_path: &Path, request_item: &str, request: &Value) -> Result<()> {
    Vault::open(vault_path.to_path_buf())?.set_managed_item(
        request_item,
        REQUEST_KIND,
        &request_envelope(request),
        &[],
        &[],
        ManagedWrite {
            controller: REQUEST_WRITER,
            writer: REQUEST_WRITER,
            operation_id: request.get("request_id").and_then(Value::as_str),
        },
    )
}

pub(super) fn update_request(
    vault_path: &Path,
    request_item: &str,
    request: &Value,
    status: &str,
    weles: Option<&Value>,
) -> Result<()> {
    let mut updated = request.clone();
    let object = updated
        .as_object_mut()
        .context("credential request is not an object")?;
    object.insert("status".to_string(), Value::String(status.to_string()));
    object.insert("updated_at".to_string(), Value::String(now_iso()));
    if let Some(response) = weles {
        object.insert("weles".to_string(), response.clone());
    }
    save_request(vault_path, request_item, &updated)
}

pub(super) fn item_revision(vault: &Vault, id: &str) -> Option<u64> {
    let item = vault.doc().get("items")?.get(id)?;
    if item.get("state").and_then(Value::as_str) == Some("trashed") {
        return None;
    }
    item.get("revision").and_then(Value::as_u64)
}

pub(super) fn context_block(vault: &Vault, id: &str, key: &str) -> Option<Value> {
    let payload = vault.get_item(id).ok()?;
    schema::field(&payload, "context")
        .ok()?
        .get(key)
        .filter(|value| !value.is_null())
        .cloned()
}

pub(super) fn context_string(vault: &Vault, id: &str, key: &str) -> Option<String> {
    let payload = vault.get_item(id).ok()?;
    schema::field(&payload, "context")
        .ok()?
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
}

pub(super) fn quarantine_tagged(vault: &Vault, id: &str) -> bool {
    vault
        .doc()
        .get("items")
        .and_then(|items| items.get(id))
        .and_then(|item| item.get("tags"))
        .and_then(Value::as_array)
        .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(QUARANTINE_TAG)))
}

pub(super) fn record_quarantined(vault: &Vault, credential_id: &str) -> bool {
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

pub(super) fn quarantine_active(vault: &Vault, credential_id: &str) -> bool {
    if record_quarantined(vault, credential_id) || quarantine_tagged(vault, credential_id) {
        return true;
    }
    context_block(vault, credential_id, "quarantine")
        .is_some_and(|block| block.get("state").and_then(Value::as_str) == Some(STATE_QUARANTINED))
}

// unmanaged, managed, adopting, or quarantined. An unknown stored state is a
// refusal, never a guess.
pub(super) fn lifecycle_state(vault: &Vault, credential_id: &str) -> Result<String> {
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

pub(super) fn refuse_quarantined(
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

// Canonical context blocks are written through the item's own management
// authority so the envelope keeps its provenance. A staged revision is never
// silently dropped: metadata waits until the staging is resolved.
pub(super) fn store_context(vault: &mut Vault, id: &str, blocks: &[(&str, Value)]) -> Result<()> {
    let entry = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(id))
        .cloned()
        .with_context(|| format!("no item: {id}"))?;
    if entry.get("state").and_then(Value::as_str) != Some("active") {
        bail!("{id} is not active; refusing to write credential lifecycle metadata");
    }
    if entry.get("pending").is_some() {
        bail!(
            "{id} has a staged revision; resolve it before writing credential lifecycle metadata"
        );
    }
    let kind = entry
        .get("kind")
        .and_then(Value::as_str)
        .context("canonical item has no kind")?
        .to_string();
    let mut payload = vault.get_item(id)?;
    let context = payload
        .get_mut("context")
        .and_then(Value::as_object_mut)
        .context("canonical item has no mutable context object")?;
    for (key, value) in blocks {
        if value.is_null() {
            context.remove(*key);
        } else {
            context.insert((*key).to_string(), value.clone());
        }
    }
    let tags: Vec<String> = entry
        .get("tags")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let recipients = vault.item_recipient_uids(id);
    let management = entry.get("management").cloned().unwrap_or_default();
    if management.get("mode").and_then(Value::as_str) == Some("managed") {
        let controller = management
            .get("controller")
            .and_then(Value::as_str)
            .context("managed item has no controller")?;
        let writer = entry
            .get("current")
            .and_then(|current| current.get("written_by"))
            .and_then(Value::as_str)
            .context("managed item has no active writer")?;
        return vault.set_managed_item(
            id,
            &kind,
            &payload,
            &recipients,
            &tags,
            ManagedWrite {
                controller,
                writer,
                operation_id: None,
            },
        );
    }
    vault.set_item(id, &kind, &payload, &recipients, &tags)
}

pub(super) fn item_matches_request(
    vault: &Vault,
    credential_id: &str,
    request_id: &str,
    operation: &str,
    account_email: Option<&str>,
) -> bool {
    vault.get_item(credential_id).is_ok_and(|payload| {
        schema::field(&payload, "context")
            .ok()
            .and_then(Value::as_object)
            .is_some_and(|context| {
                context.get("request_id").and_then(Value::as_str) == Some(request_id)
                    && context.get("operation").and_then(Value::as_str) == Some(operation)
                    && account_email.is_none_or(|email| {
                        context.get("account_ref").and_then(Value::as_str) == Some(email)
                            && schema::field(&payload, "username")
                                .ok()
                                .and_then(Value::as_str)
                                == Some(email)
                    })
            })
    })
}

pub(super) fn pending_matches_request(
    vault: &Vault,
    credential_id: &str,
    request_id: &str,
    field: &str,
    writer: &str,
) -> bool {
    vault
        .doc()
        .get("items")
        .and_then(|items| items.get(credential_id))
        .and_then(|item| item.get("pending"))
        .and_then(Value::as_object)
        .is_some_and(|pending| {
            pending.get("operation_id").and_then(Value::as_str) == Some(request_id)
                && pending.get("field").and_then(Value::as_str) == Some(field)
                && pending.get("written_by").and_then(Value::as_str) == Some(writer)
        })
}

// One authorization decision over eight independent coordinates, none of which
// this function can derive from the others: who is writing, as which operation,
// against which field of which credential, at which revision, from which
// capture origin, and which operations the caller is allowed to perform at all.
// Grouping them into a struct would only move the same eight names one line up
// while adding a type whose sole purpose is to satisfy a counter, so the lint is
// answered here rather than obeyed. `-D warnings` in the release quality gate
// means an unanswered lint is not a style note: it stops the product shipping.
#[allow(clippy::too_many_arguments)]
pub(crate) fn authorize_managed_write(
    vault: &Vault,
    credential_id: &str,
    field: &str,
    writer: &str,
    operation_id: &str,
    allowed_operations: &[&str],
    expected_revision: u64,
    capture_origin: Option<&str>,
) -> Result<()> {
    let request_item = request_item_id(credential_id);
    let request = vault
        .get_item(&request_item)
        .and_then(request_payload)
        .context("managed write has no active credential operation")?;
    let request_operation = request
        .get("operation")
        .and_then(Value::as_str)
        .context("credential operation has no operation")?;
    if !allowed_operations.contains(&request_operation)
        || request.get("version").and_then(Value::as_str) != Some(WIRE_VERSION)
        || request.get("request_id").and_then(Value::as_str) != Some(operation_id)
        || request.get("credential_id").and_then(Value::as_str) != Some(credential_id)
        || request.get("field").and_then(Value::as_str) != Some(field)
        || request.get("consumer").and_then(Value::as_str) != Some(writer)
        || request.get("baseline_revision").and_then(Value::as_u64) != Some(expected_revision)
        || !matches!(
            request.get("status").and_then(Value::as_str),
            Some("submitting" | "pending")
        )
    {
        bail!("managed write does not match the active credential operation");
    }
    // A generic provider's acquisition is bound to the exact origin the caller
    // declared: Weles echoes back the origin it actually captured at, so a
    // write from anywhere else -- or one that presents an origin for an
    // operation that declared none -- is not this operation's write.
    if request.get("signup_origin").and_then(Value::as_str) != capture_origin {
        bail!(
            "managed write capture origin is not the signup origin this credential operation declared"
        );
    }
    if quarantine_active(vault, credential_id) {
        bail!("{credential_id} is quarantined; refusing every managed write until it is resolved");
    }
    match request_operation {
        "acquire" => {
            if expected_revision != u64::MIN || live_item_exists(vault, credential_id) {
                bail!("credential acquisition requires an absent item at baseline revision zero");
            }
        }
        // adopt never authorizes a remote write: Skarbiec itself stages the
        // operator-supplied candidate and Weles only returns a verdict.
        "adopt" => {
            bail!("credential adopt stages locally and authorizes no Weles managed write");
        }
        // rotate, reset, and verify all stage against a live managed item;
        // remove trashes one. reset differs from rotate only in whether the
        // current provider password was known, never in local authority.
        "rotate" | "reset" | "verify" | "remove" => {
            if item_revision(vault, credential_id) != Some(expected_revision)
                || !inbox::managed_by_weles(vault, credential_id)
            {
                bail!("credential mutation baseline is no longer current and managed");
            }
        }
        other => bail!("credential operation {other} cannot authorize a managed write"),
    }
    Ok(())
}
