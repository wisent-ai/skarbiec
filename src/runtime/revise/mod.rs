// Write some fields of an owner-controlled item as its next revision,
// keeping every other field, its context, kind, tags and recipients. The
// value replaced stays in the item's saved versions. Commands that change a
// credential somewhere else and then here — or here first and then there —
// write the item through this, so a revision carries the same shape whichever
// command wrote it.

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::core::{vault::Vault, vault_path};

/// Set each `(field, value)` in `id`'s fields as one new revision, and answer
/// that revision.
pub(crate) fn fields(id: &str, values: &[(&str, &str)]) -> Result<u64> {
    let mut vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "revise")?;
    let mut payload = vault.get_item(id)?;
    let kind = payload["kind"].as_str().with_context(|| format!("{id} records no kind"))?.to_string();
    let held = payload
        .get_mut("fields")
        .and_then(Value::as_object_mut)
        .with_context(|| format!("{id} has no fields object"))?;
    for (field, value) in values {
        held.insert((*field).to_string(), json!(value));
    }
    let recipients = vault.item_recipient_uids(id)?;
    let tags = {
        let entry = vault.doc().get("items").and_then(|items| items.get(id)).with_context(|| format!("no item: {id}"))?;
        crate::core::vault::entry_texts(id, entry, "tags")?
    };
    vault.set_item(id, &kind, &payload, &recipients, &tags)?;
    vault.item_revision(id)
}

/// Store a secret a provider has just issued in place of one it revoked —
/// the old value no longer works anywhere, so the new one must not be lost.
/// When the vault cannot take it, it is written to an owner-only file beside
/// the vault and the refusal names that file; `provider` names who revoked
/// the old one.
pub(crate) fn issued(id: &str, field: &str, value: &str, provider: &str) -> Result<u64> {
    let error = match fields(id, &[(field, value)]) {
        Ok(revision) => return Ok(revision),
        Err(error) => error,
    };
    let kept = vault_path().with_extension(format!("{id}.{field}"));
    match crate::core::vault::atomic_write(&kept, value.as_bytes()) {
        Ok(()) => Err(error.context(format!(
            "{provider} revoked {id}'s old {field} and the vault could not take the new one; it is in {} (owner only) — store it with set, then delete the file",
            kept.display()
        ))),
        Err(undo) => Err(error.context(format!(
            "{provider} revoked {id}'s old {field} and neither the vault nor {} could take the new one ({undo:#}); revoke it with {provider} and issue another",
            kept.display()
        ))),
    }
}
