// Reading one legacy item and writing what it becomes: its canonical id, its
// recipients, and each revision re-encrypted under the current envelope.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::core::vault::Vault;
use crate::core::{crypto, schema};

pub(super) fn canonical_item_id(id: &str) -> String {
    id.strip_prefix("request:credential/")
        .map(|suffix| format!("operation:credential/{suffix}"))
        .unwrap_or_else(|| id.to_string())
}

fn decrypt_payload(ciphertext: &str, legacy_kind: &str) -> Result<(String, Value)> {
    let plain = crypto::decrypt(ciphertext).context("decrypt legacy revision")?;
    let legacy: Value = serde_json::from_str(&plain).context("parse legacy revision JSON")?;
    schema::migrate_legacy(legacy_kind, legacy)
}

fn operation_id(payload: &Value) -> Value {
    schema::field(payload, "context")
        .ok()
        .and_then(Value::as_object)
        .and_then(|context| context.get("request_id"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn recipient_fingerprints(vault: &Vault, entry: &Value) -> Vec<String> {
    let mut recipients: Vec<String> = entry
        .get("recipients")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    recipients.push(vault.owner_uid().to_string());
    let mut fingerprints = Vec::new();
    for uid in recipients {
        if let Some(fingerprint) = vault.recipient_fpr(&uid) {
            if !fingerprints.contains(&fingerprint) {
                fingerprints.push(fingerprint);
            }
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
    created_at: Value,
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

pub(super) fn migrate_item(
    vault: &Vault,
    id: &str,
    entry: &Value,
) -> Result<(Value, Vec<String>, usize)> {
    if entry.get("format").and_then(Value::as_u64) == Some(crate::core::vault::current_envelope()) {
        let payload = entry
            .get("current")
            .context("v2 item has no current revision")
            .and_then(revision_payload)?;
        let fields = schema::fields(&payload)?.keys().cloned().collect();
        return Ok((entry.clone(), fields, usize::MIN));
    }
    let legacy_kind = entry
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("opaque");
    let current_ciphertext = entry
        .get("current")
        .and_then(Value::as_str)
        .context("legacy item has no current ciphertext")?;
    let fingerprints = recipient_fingerprints(vault, entry);
    if fingerprints.is_empty() {
        bail!("{id} has no valid recipient fingerprint");
    }
    let writer = entry
        .get("written_by")
        .and_then(Value::as_str)
        .unwrap_or_else(|| vault.owner_uid());
    let mut history = Vec::new();
    let mut revision: u64 = std::iter::once(()).count().try_into()?;
    if let Some(legacy_history) = entry.get("history").and_then(Value::as_array) {
        for legacy_revision in legacy_history {
            let ciphertext = legacy_revision
                .get("cipher")
                .or_else(|| legacy_revision.get("ciphertext"))
                .and_then(Value::as_str)
                .context("legacy history revision has no ciphertext")?;
            let created_at = legacy_revision
                .get("at")
                .or_else(|| legacy_revision.get("created_at"))
                .cloned()
                .unwrap_or(Value::Null);
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
                .checked_add(std::iter::once(()).count().try_into()?)
                .context("revision overflow")?;
        }
    }
    let current_at = entry
        .get("updated_at")
        .or_else(|| entry.get("created_at"))
        .cloned()
        .unwrap_or(Value::Null);
    let (kind, payload, current) = canonical_revision(
        current_ciphertext,
        legacy_kind,
        &fingerprints,
        revision,
        current_at.clone(),
        writer,
    )?;
    // Carried across verbatim, and deliberately not put through the tag
    // registry. A migration introduces no tag: it re-envelopes tags the item
    // has carried since before the registry was executable. Judging them here
    // would make a v1 vault holding one unregistered tag impossible to migrate
    // at all, which is the opposite of the repair -- the tag has to reach v2
    // before an operator can retag it away.
    let tags: Vec<Value> = entry
        .get("tags")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // `managed:weles` is a reserved tag: the CLI and `import` refuse it by name,
    // so only an authenticated Weles managed write ever put it on a legacy item.
    // That tag is therefore the item's own declaration that Weles controls it.
    // The writer identity recorded beside it is a mutable name, and testing it
    // for a `weles-` prefix meant renaming a consumer silently stripped the
    // declared tag and downgraded the item's management authority from managed
    // to owner or external, with nothing raised. The declaration decides.
    let managed_by_weles = tags.iter().any(|tag| tag.as_str() == Some("managed:weles"));
    let management = if kind == "credential-operation" {
        json!({
            "mode": "managed",
            "controller": "skarbiec-credential-lifecycle"
        })
    } else if managed_by_weles {
        json!({"mode": "managed", "controller": "weles"})
    } else if writer == vault.owner_uid() {
        json!({"mode": "owner", "controller": vault.owner_uid()})
    } else {
        json!({"mode": "external", "controller": writer})
    };
    let state = if entry
        .get("deleted")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        "trashed"
    } else {
        "active"
    };
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
        "created_at": entry.get("created_at").cloned().unwrap_or(current_at.clone()),
        "updated_at": current_at,
        "deleted_at": entry.get("deleted_at").cloned().unwrap_or(Value::Null),
        "recipients": entry.get("recipients").cloned().unwrap_or_else(|| json!([])),
        "tags": tags,
        "current": current,
        "history": history,
    });
    let fields = schema::fields(&payload)?.keys().cloned().collect();
    Ok((canonical, fields, revision as usize))
}

pub(super) fn revision_payload(revision: &Value) -> Result<Value> {
    let cipher = revision
        .get("ciphertext")
        .and_then(Value::as_str)
        .context("v2 revision has no ciphertext")?;
    let plain = crypto::decrypt(cipher)?;
    serde_json::from_str(&plain).context("v2 revision payload is not JSON")
}
