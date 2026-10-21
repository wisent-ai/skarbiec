// Reading one legacy item and writing what it becomes: its canonical id, its
// recipients, and each revision re-encrypted under the current envelope.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::num::NonZeroU64;

use crate::core::vault::{ManagementMode, Vault};
use crate::core::{crypto, schema};

/// The v2 id of a legacy item: a credential request becomes the credential
/// operation it names, and every other id is kept as it is.
pub(super) fn canonical_item_id(id: &str) -> String {
    match id.strip_prefix("request:credential/") {
        Some(suffix) => format!("operation:credential/{suffix}"),
        None => id.to_string(),
    }
}

fn decrypt_payload(ciphertext: &str, legacy_kind: &str) -> Result<(String, Value)> {
    let plain = crypto::decrypt(ciphertext).context("decrypt legacy revision")?;
    let legacy: Value = serde_json::from_str(&plain).context("parse legacy revision JSON")?;
    schema::migrate_legacy(legacy_kind, legacy)
}

/// The credential operation a payload belongs to: the request id its context
/// records, or none for a payload whose context names no request.
fn operation_id(payload: &Value) -> Option<Value> {
    payload
        .get("context")?
        .as_object()?
        .get("request_id")
        .cloned()
}

/// The fingerprints a legacy item is re-enveloped to: every recipient it
/// lists, the owner, and the recovery key. A listed uid the vault holds no
/// fingerprint for (a recipient removed since) is not carried over, and that
/// is said, since the migrated item is then readable by fewer people than the
/// legacy one.
fn recipient_fingerprints(vault: &Vault, id: &str, listed: &[String]) -> Vec<String> {
    let owner = vault.owner_uid().to_string();
    let mut fingerprints = Vec::new();
    for uid in listed.iter().chain(std::iter::once(&owner)) {
        match vault.recipient_fpr(uid) {
            Some(fingerprint) => {
                if !fingerprints.contains(&fingerprint) {
                    fingerprints.push(fingerprint);
                }
            }
            None => eprintln!(
                "skarbiec: {id} lists recipient {uid}, whose fingerprint the vault no longer holds; the migrated item is not encrypted to it"
            ),
        }
    }
    let recovery = vault.recovery_fpr().to_string();
    if !recovery.is_empty() && !fingerprints.contains(&recovery) {
        fingerprints.push(recovery);
    }
    fingerprints
}

fn canonical_revision(
    ciphertext: &str,
    legacy_kind: &str,
    fingerprints: &[String],
    revision: u64,
    created_at: &Value,
    writer: &str,
) -> Result<(String, Value, Value)> {
    let (kind, payload) = decrypt_payload(ciphertext, legacy_kind)?;
    let canonical_ciphertext = crypto::encrypt_to(fingerprints, &serde_json::to_string(&payload)?)?;
    let record = json!({
        "revision": revision,
        "kind": kind,
        "created_at": created_at,
        "written_by": writer,
        "operation_id": operation_id(&payload),
        "ciphertext": canonical_ciphertext,
    });
    Ok((kind, payload, record))
}

/// The item in the v2 envelope, its field names, and how many revisions the
/// migration re-enveloped: none for an item already in the current envelope.
///
/// A v1 entry always records its type, creation and update times, recipients,
/// tags, history, deleted flag and deletion time, and each history revision
/// its time and ciphertext; one missing any of them is refused naming the
/// field. Only `written_by` may be absent: v1 recorded it once writers other
/// than the owner existed, so an entry without it was written by the owner.
pub(super) fn migrate_item(
    vault: &Vault,
    id: &str,
    entry: &Value,
) -> Result<(Value, Vec<String>, Option<usize>)> {
    if entry.get("format").and_then(Value::as_u64) == Some(crate::core::vault::current_envelope()) {
        let payload = entry
            .get("current")
            .context("v2 item has no current revision")
            .and_then(revision_payload)?;
        let fields = schema::fields(&payload)?.keys().cloned().collect();
        return Ok((entry.clone(), fields, None));
    }
    let recorded = |name: &str| {
        entry
            .get(name)
            .with_context(|| format!("legacy item {id} records no {name}"))
    };
    let legacy_kind = recorded("type")?
        .as_str()
        .with_context(|| format!("legacy item {id} records a type that is not text"))?;
    let current_ciphertext = entry
        .get("current")
        .and_then(Value::as_str)
        .context("legacy item has no current ciphertext")?;
    let recipients = crate::core::vault::entry_texts(id, entry, "recipients")?;
    let fingerprints = recipient_fingerprints(vault, id, &recipients);
    if fingerprints.is_empty() {
        bail!("{id} has no valid recipient fingerprint");
    }
    let writer = match entry.get("written_by") {
        None => vault.owner_uid(),
        Some(named) => named
            .as_str()
            .with_context(|| format!("legacy item {id} records a writer that is not text"))?,
    };
    let legacy_history = recorded("history")?
        .as_array()
        .with_context(|| format!("legacy item {id} records a history that is not a list"))?;
    let mut history = Vec::new();
    // Revisions are numbered from the first, as every v2 write numbers them.
    let mut revision = NonZeroU64::MIN.get();
    for legacy_revision in legacy_history {
        let ciphertext = legacy_revision
            .get("cipher")
            .or_else(|| legacy_revision.get("ciphertext"))
            .and_then(Value::as_str)
            .context("legacy history revision has no ciphertext")?;
        let created_at = legacy_revision
            .get("at")
            .or_else(|| legacy_revision.get("created_at"))
            .with_context(|| format!("a legacy history revision of {id} records no time"))?;
        let (_, _, record) = canonical_revision(
            ciphertext,
            legacy_kind,
            &fingerprints,
            revision,
            created_at,
            writer,
        )?;
        history.push(record);
        revision = revision
            .checked_add(NonZeroU64::MIN.get())
            .context("revision overflow")?;
    }
    let current_at = recorded("updated_at")?;
    let (kind, payload, current) = canonical_revision(
        current_ciphertext,
        legacy_kind,
        &fingerprints,
        revision,
        current_at,
        writer,
    )?;
    // Carried across verbatim, and deliberately not put through the tag
    // registry. A migration introduces no tag: it re-envelopes tags the item
    // has carried since before the registry was executable. Judging them here
    // would make a v1 vault holding one unregistered tag impossible to migrate
    // at all, which is the opposite of the repair -- the tag has to reach v2
    // before an operator can retag it away.
    let tags = recorded("tags")?
        .as_array()
        .with_context(|| format!("legacy item {id} records tags that are not a list"))?
        .clone();
    // `managed:weles` is a reserved tag: the CLI and `import` refuse it by name,
    // so only an authenticated Weles managed write ever put it on a legacy item.
    // That tag is therefore the item's own declaration that Weles controls it;
    // the writer identity recorded beside it is a mutable name and decides
    // nothing here.
    let managed_by_weles = tags.iter().any(|tag| tag.as_str() == Some("managed:weles"));
    let management = if kind == "credential-operation" {
        json!({
            "mode": ManagementMode::Managed.as_str(),
            "controller": "skarbiec-credential-lifecycle"
        })
    } else if managed_by_weles {
        json!({"mode": ManagementMode::Managed.as_str(), "controller": "weles"})
    } else if writer == vault.owner_uid() {
        json!({"mode": ManagementMode::Owner.as_str(), "controller": vault.owner_uid()})
    } else {
        json!({"mode": ManagementMode::External.as_str(), "controller": writer})
    };
    let deleted = recorded("deleted")?.as_bool().with_context(|| {
        format!("legacy item {id} records a deleted flag that is not true or false")
    })?;
    let state = if deleted { "trashed" } else { "active" };
    // A v1 envelope has no `item_uid`, and this builds the v2 entry from scratch, so
    // the identity is minted here rather than left for the backfill. A legacy
    // item that somehow carries one keeps it: an `item_uid` is never reissued.
    let item_uid = match crate::core::vault::entry_item_uid(entry) {
        Some(existing) => existing.to_string(),
        None => crate::core::vault::mint_item_uid()?,
    };
    let canonical = json!({
        "format": crate::core::vault::current_envelope(),
        "item_uid": item_uid,
        "kind": kind,
        "state": state,
        "revision": revision,
        "management": management,
        "created_at": recorded("created_at")?,
        "updated_at": current_at,
        "deleted_at": recorded("deleted_at")?,
        "recipients": recipients,
        "tags": tags,
        "current": current,
        "history": history,
    });
    let fields = schema::fields(&payload)?.keys().cloned().collect();
    Ok((canonical, fields, Some(usize::try_from(revision)?)))
}

pub(super) fn revision_payload(revision: &Value) -> Result<Value> {
    let cipher = revision
        .get("ciphertext")
        .and_then(Value::as_str)
        .context("v2 revision has no ciphertext")?;
    let plain = crypto::decrypt(cipher)?;
    serde_json::from_str(&plain).context("v2 revision payload is not JSON")
}
