// Where a credential operation and its sealed contract are kept: the item ids
// they live under, and the only two writers that may put them there.

use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

use crate::core::schema;
use crate::core::vault::{ManagedWrite, Vault};

use super::super::common::now_iso;
use super::super::wire::record_envelope;
use super::super::{REQUEST_KIND, REQUEST_WRITER, SEAL_KIND};

pub(in crate::credential) fn request_item_id(credential_id: &str) -> String {
    format!("operation:credential/{credential_id}")
}

// The sealed directory contract survives item absence: adopt and acquire copy
// it into the item they create, and the item keeps it from then on.
pub(crate) fn seal_item_id(credential_id: &str) -> String {
    format!("directory:credential/{credential_id}")
}

// Items the credential lifecycle owns end to end: operation records and sealed
// directory contracts. Both are written only through `save_record`, under a
// managed authority whose controller is `REQUEST_WRITER`; the vault refuses any
// later write that names a different authority, so that authority is the
// record's own declaration of who owns it and it cannot be forged through an
// item API. The id is not authoritative: it is a mutable human-chosen name, and
// deriving the write protection from how it happens to be spelled meant a
// rename silently removed the protection with nothing raised. An id this vault
// does not hold is not owned by anything -- if something else takes the name
// first, the lifecycle's own managed write is the loud failure ("controlled by
// a different management authority").
// No item API may write, import, or accept a donation for one of these.
//
// Ownership spans both kinds and is deliberately not narrowed to one. The kind
// says which family a record belongs to; the managed authority says the
// lifecycle owns it. A seal written before `SEAL_KIND` existed still carries
// `REQUEST_KIND`, and it is owned exactly as much as one written today, so
// testing for either is what keeps an existing seal protected.
pub(crate) fn lifecycle_owned_item(vault: &Vault, id: &str) -> bool {
    let Some(item) = vault.doc().get("items").and_then(|items| items.get(id)) else {
        return false;
    };
    if !matches!(
        item.get("kind").and_then(Value::as_str),
        Some(REQUEST_KIND) | Some(SEAL_KIND)
    ) {
        return false;
    }
    item.get("management").is_some_and(|management| {
        management.get("mode").and_then(Value::as_str) == Some("managed")
            && management.get("controller").and_then(Value::as_str) == Some(REQUEST_WRITER)
    })
}

pub(in crate::credential) fn live_item_exists(vault: &Vault, id: &str) -> bool {
    vault
        .list(false)
        .iter()
        .any(|entry| entry.get("id").and_then(Value::as_str) == Some(id))
}

// One writer, two declared families. The kind travels with the record instead
// of being assumed, because assuming it is what made a seal and an operation
// record indistinguishable once written.
fn save_record(vault_path: &Path, item: &str, kind: &str, record: &Value) -> Result<()> {
    Vault::open(vault_path.to_path_buf())?.set_managed_item(
        item,
        kind,
        &record_envelope(kind, record),
        &[],
        &[],
        ManagedWrite {
            controller: REQUEST_WRITER,
            writer: REQUEST_WRITER,
            operation_id: record.get("request_id").and_then(Value::as_str),
        },
    )
}

pub(in crate::credential) fn save_request(
    vault_path: &Path,
    request_item: &str,
    request: &Value,
) -> Result<()> {
    save_record(vault_path, request_item, REQUEST_KIND, request)
}

// The sealed directory contract, declared as one. `seal_directory` is the only
// caller: a seal is written by sealing and by resealing, and by nothing else.
pub(in crate::credential) fn save_seal(
    vault_path: &Path,
    seal_item: &str,
    sealed: &Value,
) -> Result<()> {
    save_record(vault_path, seal_item, SEAL_KIND, sealed)
}

pub(in crate::credential) fn update_request(
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

pub(in crate::credential) fn item_revision(vault: &Vault, id: &str) -> Option<u64> {
    let item = vault.doc().get("items")?.get(id)?;
    if item.get("state").and_then(Value::as_str) == Some("trashed") {
        return None;
    }
    item.get("revision").and_then(Value::as_u64)
}

pub(in crate::credential) fn context_block(vault: &Vault, id: &str, key: &str) -> Option<Value> {
    let payload = vault.get_item(id).ok()?;
    schema::field(&payload, "context")
        .ok()?
        .get(key)
        .filter(|value| !value.is_null())
        .cloned()
}

pub(in crate::credential) fn context_string(vault: &Vault, id: &str, key: &str) -> Option<String> {
    let payload = vault.get_item(id).ok()?;
    schema::field(&payload, "context")
        .ok()?
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
}
