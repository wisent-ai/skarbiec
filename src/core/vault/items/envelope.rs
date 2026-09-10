// Building one item's stored envelope: ciphertext, recipients, revision,
// history and the metadata a reader can see without decrypting anything.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::core::vault::{
    current_envelope, entry_item_uid, mint_item_uid, now, Vault, WritePolicy,
};
use crate::core::{crypto, schema};

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
            .map(|write| json!({"mode": "managed", "controller": write.controller}));
        let preserve_metadata = policy.managed.is_some();
        let operation_id = policy.managed.and_then(|write| write.operation_id);
        schema::validate_payload(payload, item_kind)?;
        let previous = self
            .doc
            .get("items")
            .and_then(Value::as_object)
            .and_then(|items| items.get(id))
            .cloned();
        if previous.as_ref().is_some_and(|entry| {
            entry.get("format").and_then(Value::as_u64) != Some(current_envelope())
        }) {
            bail!("{id} still uses the legacy envelope; run migrate-v2 before updating it");
        }
        if let (Some(previous), Some(requested)) = (&previous, &requested_management) {
            if let Some(existing) = previous.get("management") {
                if existing != requested {
                    bail!("{id} is controlled by a different management authority");
                }
            }
        }
        if requested_management.is_none()
            && previous.as_ref().is_some_and(|entry| {
                entry
                    .get("management")
                    .and_then(|management| management.get("mode"))
                    .and_then(Value::as_str)
                    != Some("owner")
            })
        {
            let existing = previous.as_ref().context("protected item disappeared")?;
            let current_payload = self.get_item(id)?;
            let current_tags = existing
                .get("tags")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
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
        let effective_recipients = if preserve_metadata {
            previous
                .as_ref()
                .and_then(|entry| entry.get("recipients"))
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_else(|| recipient_uids.to_vec())
        } else {
            recipient_uids.to_vec()
        };
        let effective_tags = if preserve_metadata {
            previous
                .as_ref()
                .and_then(|entry| entry.get("tags"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_else(|| tags.iter().cloned().map(Value::String).collect())
        } else {
            tags.iter().cloned().map(Value::String).collect()
        };
        // Every item write in this crate arrives here -- `set`, `set-json`,
        // `import`, the cross-vault copy, share, revoke, the emergency grant,
        // the bond pull, donation-accept, the credential lifecycle and the
        // HTTP acquire -- so the tag registry is enforced once, where the
        // stored list is finally known, rather than once per caller with the
        // next caller forgetting.
        //
        // Against what the item already carries, not against nothing: this is
        // the one write that legitimately restates a tag list it did not
        // author, because an absent `--tags` means "leave this as it is".
        let carried_tags: &[Value] = previous
            .as_ref()
            .and_then(|entry| entry.get("tags"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        schema::ensure_registered_tags(carried_tags, &effective_tags)?;
        // The item's permanent identity, decided once and never again.
        //
        // This is the one write that rebuilds the whole envelope from scratch,
        // so every field it does not carry forward is a field it destroys. The
        // precedence is what makes the guarantee absolute rather than
        // best-effort: an existing item's own uid always wins, so no write of
        // any kind -- rotation, retag, share, revoke, managed lifecycle write,
        // restore-version, or a forced cross-vault overwrite -- can replace an
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
        let management = requested_management
            .or_else(|| {
                previous
                    .as_ref()
                    .and_then(|entry| entry.get("management"))
                    .cloned()
            })
            .unwrap_or_else(|| {
                let controller = writer.unwrap_or_else(|| self.owner_uid());
                let mode = if controller == self.owner_uid() {
                    "owner"
                } else {
                    "external"
                };
                json!({"mode": mode, "controller": controller})
            });
        let revision = previous
            .as_ref()
            .and_then(|entry| entry.get("revision"))
            .and_then(Value::as_u64)
            .unwrap_or_default()
            .checked_add(std::iter::once(()).count() as u64)
            .context("item revision overflow")?;
        let fprs = self.fprs_for(&effective_recipients);
        let cipher = crypto::encrypt_to(&fprs, &serde_json::to_string(payload)?)?;
        let stamp = now();
        let mut history = previous
            .as_ref()
            .and_then(|entry| entry.get("history"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if let Some(current) = previous.as_ref().and_then(|entry| entry.get("current")) {
            history.push(current.clone());
        }
        let created = previous
            .as_ref()
            .and_then(|entry| entry.get("created_at"))
            .cloned()
            .unwrap_or_else(|| json!(stamp));
        let written_by = writer.unwrap_or_else(|| self.owner_uid()).to_string();
        let stored_tags = effective_tags.len();
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
            "process": std::env::args().next().unwrap_or_default(),
            "parent_pid": parent_pid,
            "parent_process": parent_process,
        });
        Ok((entry, audit))
    }
}
