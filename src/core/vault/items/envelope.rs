// Building one item's stored envelope: ciphertext, recipients, revision,
// history and the metadata a reader can see without decrypting anything.

use std::num::NonZeroU64;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::core::vault::items::duplicates;
use crate::core::vault::{
    current_envelope, entry_item_uid, entry_texts, mint_item_uid, now, ManagementMode, Vault,
    WritePolicy,
};
use crate::core::{crypto, schema};

/// The tags an entry stores, as the values the envelope writes back. A list
/// with an entry that is not text, or tags that are not a list, is refused
/// rather than read as none and written over.
fn stored_tags(id: &str, entry: &Value) -> Result<Vec<Value>> {
    Ok(entry_texts(id, entry, "tags")?
        .into_iter()
        .map(Value::String)
        .collect())
}

impl Vault {
    pub(in crate::core::vault) fn prepare_item_with_writer(
        &self,
        id: &str,
        item_kind: &str,
        payload: &Value,
        recipient_uids: &[String],
        tags: &[String],
        policy: WritePolicy<'_>,
    ) -> Result<(Value, Value)> {
        let writer = policy.writer;
        let requested_management = policy
            .managed
            .map(|write| json!({"mode": ManagementMode::Managed.as_str(), "controller": write.controller}));
        let preserve_metadata = policy.managed.is_some();
        let operation_id = policy.managed.and_then(|write| write.operation_id);
        schema::validate_payload(payload, item_kind)?;
        // Whose account this login signs in as. A reference to an item that is
        // not there would send every later second-factor lookup to nothing, so
        // it is refused where the vault is known rather than at read time.
        if let Some(reference) = payload
            .get("context")
            .and_then(|context| context.get(schema::IDENTITY_REFERENCE))
            .and_then(Value::as_str)
        {
            let held = self
                .doc
                .get("items")
                .and_then(Value::as_object)
                .and_then(|items| items.get(reference));
            match held {
                Some(entry)
                    if entry.get("state").and_then(Value::as_str) == Some("active")
                        && entry.get("kind").and_then(Value::as_str) == Some("identity") => {}
                Some(_) => bail!(
                    "context.{} names {reference}, which is not an active identity item",
                    schema::IDENTITY_REFERENCE
                ),
                None => bail!(
                    "context.{} names {reference}, and this vault holds no such item",
                    schema::IDENTITY_REFERENCE
                ),
            }
        }
        let previous = self
            .doc
            .get("items")
            .and_then(Value::as_object)
            .and_then(|items| items.get(id))
            .cloned();
        if previous.as_ref().is_some_and(|entry| {
            entry.get("format").and_then(Value::as_u64) != Some(current_envelope())
        }) {
            bail!("{id} still uses the legacy envelope; run `skarbiec upgrade --apply` before updating it");
        }
        if let (Some(previous), Some(requested)) = (&previous, &requested_management) {
            if let Some(existing) = previous.get("management") {
                if existing != requested {
                    bail!("{id} is controlled by a different management authority");
                }
            }
        }
        if requested_management.is_none()
            && previous
                .as_ref()
                .is_some_and(|entry| ManagementMode::of(entry) != Some(ManagementMode::Owner))
        {
            let existing = previous.as_ref().context("protected item disappeared")?;
            let current_payload = self.get_item(id)?;
            let current_tags = stored_tags(id, existing)?;
            let requested_tags: Vec<Value> = tags.iter().cloned().map(Value::String).collect();
            if existing.get("state").and_then(Value::as_str) != Some("active")
                || existing.get("kind").and_then(Value::as_str) != Some(item_kind)
                || current_payload != *payload
                || current_tags != requested_tags
            {
                bail!(
                    "{id} payload and protected metadata may only change through its controlling lifecycle"
                );
            }
        }
        // A previous recipients list is kept as stored; one that is not a list
        // of text is refused, since read with its odd entries dropped the
        // item was re-encrypted to fewer recipients with nothing said.
        let stored_recipients = previous.as_ref().filter(|entry| {
            entry
                .get("recipients")
                .is_some_and(|listed| !listed.is_null())
        });
        let effective_recipients = match (preserve_metadata, stored_recipients) {
            (true, Some(entry)) => crate::core::vault::entry_texts(id, entry, "recipients")?,
            _ => recipient_uids.to_vec(),
        };
        // A managed write keeps the tags the item already carries; every
        // other write stores the ones requested.
        let effective_tags = match (&previous, preserve_metadata) {
            (Some(entry), true) => stored_tags(id, entry)?,
            _ => tags.iter().cloned().map(Value::String).collect(),
        };
        // Every item write in this crate arrives here -- `set`, `set-json`,
        // `import`, the cross-vault copy, share, revoke, the emergency grant,
        // the bond pull, donation accept, the credential lifecycle and the
        // HTTP acquire -- so the tag registry is enforced once, where the
        // stored list is finally known, rather than once per caller with the
        // next caller forgetting.
        //
        // Against what the item already carries, not against nothing: this is
        // the one write that legitimately restates a tag list it did not
        // author, because an absent `--tags` means "leave this as it is".
        let carried_tags = match &previous {
            Some(entry) => stored_tags(id, entry)?,
            None => Vec::new(),
        };
        schema::ensure_registered_tags(&carried_tags, &effective_tags)?;
        // The item's permanent identity, decided once and never again.
        //
        // This is the one write that rebuilds the whole envelope from scratch,
        // so every field it does not carry forward is a field it destroys. The
        // precedence is what makes the guarantee absolute rather than
        // best-effort: an existing item's own uid always wins, so no write of
        // any kind -- rotation, retag, share, revoke, managed lifecycle write,
        // restore --at, or a forced cross-vault overwrite -- can replace an
        // identity that already exists. Only an item this vault has never seen
        // takes the caller's uid (a cross-vault migrate carrying the source's),
        // and only an item with neither mints a new one.
        let item_uid = match previous.as_ref().and_then(entry_item_uid) {
            Some(existing) => existing.to_string(),
            None => match policy.item_uid {
                Some(supplied) => supplied.to_string(),
                None => mint_item_uid()?,
            },
        };
        // A write that names no writer is the vault owner's own.
        let controller = match writer {
            Some(writer) => writer,
            None => self.owner_uid(),
        };
        // The management an existing item records is carried forward; one
        // that records none is damaged and refused, never re-derived.
        let management = match (requested_management, &previous) {
            (Some(requested), _) => requested,
            (None, Some(entry)) => entry
                .get("management")
                .cloned()
                .with_context(|| format!("vault item {id} records no management"))?,
            (None, None) => {
                let mode = if controller == self.owner_uid() {
                    ManagementMode::Owner
                } else {
                    ManagementMode::External
                };
                json!({"mode": mode.as_str(), "controller": controller})
            }
        };
        // A new item starts at the first revision; an existing one goes one
        // past what it records. One that records no revision is refused:
        // restarting it would hand out a revision an older version already had.
        let revision = match &previous {
            Some(entry) => entry
                .get("revision")
                .and_then(Value::as_u64)
                .with_context(|| format!("vault item {id} records no whole-number revision"))?
                .checked_add(NonZeroU64::MIN.get())
                .context("item revision overflow")?,
            None => NonZeroU64::MIN.get(),
        };
        let fprs = self.fprs_for(&effective_recipients);
        let cipher = crypto::encrypt_to(&fprs, &serde_json::to_string(payload)?)?;
        let stamp = now();
        // Earlier versions are kept. An entry that never stored a history has
        // none yet; one whose history is not a list is refused, since writing
        // it back as empty would drop every version it held.
        let mut history = match previous.as_ref().and_then(|entry| entry.get("history")) {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(versions)) => versions.clone(),
            Some(other) => bail!("vault item {id} carries history {other}, not a list"),
        };
        if let Some(current) = previous.as_ref().and_then(|entry| entry.get("current")) {
            history.push(current.clone());
        }
        let created = match &previous {
            Some(entry) => entry
                .get("created_at")
                .cloned()
                .with_context(|| format!("vault item {id} records no creation time"))?,
            None => json!(stamp),
        };
        let written_by = controller.to_string();
        let stored_tags = effective_tags.len();
        // What this item holds, as a fingerprint of its canonical payload
        // under this vault's salt. Two purposes, both answerable without
        // opening anything: a second item holding the same credential is
        // refused here, and `duplicates` reports the pairs that predate the
        // refusal.
        let salt = self
            .doc
            .get(duplicates::SALT_KEY)
            .and_then(Value::as_str)
            .context("this vault has no fingerprint salt; a write must mint one first")?;
        let print = duplicates::fingerprint(salt, payload)?;
        if let Some(items) = self.doc.get("items").and_then(Value::as_object) {
            if let Some(holder) = duplicates::holder_of(items, &print, id) {
                bail!(
                    "{holder} already holds exactly this payload; an exact duplicate is refused \
                     (rename or delete one of them, or read `skarbiec duplicates`)"
                );
            }
        }
        let mut entry = json!({
            "format": current_envelope(),
            "item_uid": item_uid,
            "kind": item_kind,
            "state": "active",
            "revision": revision,
            "management": management,
            "created_at": created,
            "updated_at": stamp,
            "recipients": effective_recipients,
            "tags": effective_tags,
            duplicates::FINGERPRINT_KEY: print,
            "current": {
                "revision": revision,
                "kind": item_kind,
                "created_at": stamp,
                "written_by": written_by,
                "operation_id": operation_id,
                "ciphertext": cipher,
            },
            "history": history,
        });
        if let Some(source) = previous.as_ref().and_then(|item| item.get("import_source")) {
            entry["import_source"] = source.clone();
        }
        // Who wrote this, in the journal, not only which owner key signed it.
        // Two subscription items lost their enumeration tags repeatedly while
        // every writer anyone could name preserved them, and the vault recorded
        // only `written_by`, which is the owner uid for every owner-mode write on
        // the host. Without the process behind the write there is nothing to ask,
        // so a tag that disappears again names its own cause.
        //
        // Both counts, because the difference is the whole signal: `tags` is what
        // this revision now carries and `tags_requested` is what the writer passed.
        // A rotation that passes none and stores the previous four is the
        // tag-preserving write working; a stored count that falls to zero names the
        // writer that emptied it.
        //
        // `append_sync`, not `append`: the queued form hands the line to a worker
        // thread, and a one-shot CLI write -- which is what every rotation on this
        // fleet is, `set-json` invoked per refresh -- exits before that thread runs.
        // The 318 rewrites of one subscription item left no journal line at all, so
        // the record built to name the writer named nobody. A vault write is a
        // mutating operation, and this file's own rule is that those journal
        // synchronously.
        let (parent_pid, parent_process) = Self::parent_process();
        let audit = json!({
            "item": id,
            "kind": item_kind,
            "revision": revision,
            "tags": stored_tags,
            "tags_requested": tags.len(),
            "pid": std::process::id(),
            "process": std::env::args().next(),
            "parent_pid": parent_pid,
            "parent_process": parent_process,
        });
        Ok((entry, audit))
    }
}
