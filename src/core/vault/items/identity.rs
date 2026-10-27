// The identity a rename cannot touch: resolving an item_uid back to the id
// that holds it, renaming, backfilling missing uids, and restoring a version.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::core::vault::{current_envelope, entry_item_uid, mint_item_uid, now, obj_mut, Vault};
use crate::core::{crypto, schema};

impl Vault {
    /// The id currently holding this `item_uid`, if any item does.
    ///
    /// This is what turns "no vault item X" into "X is now Y". Linear over the
    /// items map and reading only cleartext envelope metadata, so it costs no
    /// decryption and is safe to call from a diagnosis on a host whose gpg is
    /// the fault.
    pub fn id_for_item_uid(&self, item_uid: &str) -> Option<&str> {
        if item_uid.is_empty() {
            return None;
        }
        self.doc
            .get("items")
            .and_then(Value::as_object)?
            .iter()
            .find(|(_, entry)| entry_item_uid(entry) == Some(item_uid))
            .map(|(id, _)| id.as_str())
    }

    /// The revision of the item's current value: the number every write of a
    /// new value raises (a write, a restored version, an activated staged
    /// rotation) and that tags, recipients and renames leave as it is. It is
    /// read from the cleartext envelope, so it costs no decryption: a reader
    /// that holds a value learns whether the value it holds is still current
    /// without reading the value again.
    pub fn item_revision(&self, id: &str) -> Result<u64> {
        let entry = self
            .doc
            .get("items")
            .and_then(Value::as_object)
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        entry.get("revision").and_then(Value::as_u64).with_context(|| {
            format!("item {id} records no revision; run `skarbiec upgrade --apply` to bring it to the current envelope")
        })
    }

    /// Move one item to a new id, keeping everything that is not the id.
    ///
    /// The entry object is moved whole, so `item_uid`, history, revision,
    /// created_at, tags, recipients, management and the ciphertext itself are
    /// the same bytes at the new key. Nothing is decrypted or re-encrypted:
    /// the id is a map key, not part of the sealed payload.
    ///
    /// Improvising this with `get` + `set` under a new id + `delete` does
    /// not do the same thing. That is a copy: the new item starts at revision
    /// 1, its history is empty, `created_at` is now, tags are gone because
    /// there is no previous entry to preserve them from, and it needs the
    /// plaintext in hand to write at all.
    ///
    /// An `item_uid` is minted here when the item has none, because it is what
    /// lets a route table or a consumer config work out where the item went;
    /// renaming without one leaves exactly the untraceable gap this exists to
    /// close.
    pub fn rename_item(&mut self, from: &str, to: &str) -> Result<String> {
        if from == to {
            bail!("{from} already has that id");
        }
        if !schema::exact_token(to) {
            bail!(
                "a new item id must be one non-empty name with no NUL, newline or carriage return"
            );
        }
        let items = self
            .doc
            .get("items")
            .and_then(Value::as_object)
            .context("vault has no items section")?;
        if items.contains_key(to) {
            bail!("{to} already exists; renaming onto a live item would replace it");
        }
        let mut entry = items
            .get(from)
            .cloned()
            .with_context(|| format!("no item: {from}"))?;
        if entry.get("format").and_then(Value::as_u64) != Some(current_envelope()) {
            bail!("{from} still uses the legacy envelope; run `skarbiec upgrade --apply` before renaming it");
        }
        let item_uid = match entry_item_uid(&entry) {
            Some(existing) => existing.to_string(),
            None => {
                let minted = mint_item_uid()?;
                entry["item_uid"] = json!(minted);
                minted
            }
        };
        entry["updated_at"] = json!(now());
        let items = obj_mut(&mut self.doc, "items")?;
        items.remove(from);
        items.insert(to.to_string(), entry);
        self.save()?;
        Ok(item_uid)
    }

    /// Stamp an `item_uid` onto every item that has none.
    ///
    /// Idempotent by construction: an item that already carries one is skipped
    /// before anything is generated, so a second run mints nothing, writes no
    /// new value over an old one, and reports zero stamped. Envelope only --
    /// no payload is read, decrypted, re-encrypted or revised, and `revision`,
    /// `updated_at` and `current` are left exactly as they were, because
    /// acquiring an identifier is not a change to the credential.
    ///
    /// The vault is saved once at the end rather than per item, and only when
    /// something actually changed.
    pub fn backfill_item_uids(&mut self) -> Result<(Vec<String>, usize)> {
        // A vault with no items section yet holds no items; one whose section is not an
        // object is damaged, and stamping it would hide that.
        let none = Map::new();
        let items = match self.doc.get("items") {
            None => &none,
            Some(Value::Object(items)) => items,
            Some(other) => anyhow::bail!("the vault document's items section is {other}, not an object of items"),
        };
        let ids: Vec<String> = items
            .iter()
            .filter(|(_, entry)| entry_item_uid(entry).is_none())
            .map(|(id, _)| id.clone())
            .collect();
        let total = items.len();
        if ids.is_empty() {
            return Ok((ids, total));
        }
        for id in &ids {
            let minted = mint_item_uid()?;
            let entry = obj_mut(&mut self.doc, "items")?
                .get_mut(id)
                .and_then(Value::as_object_mut)
                .with_context(|| format!("no item: {id}"))?;
            entry.insert("item_uid".to_string(), json!(minted));
        }
        self.save()?;
        Ok((ids, total))
    }

    // Restoring history creates a fresh canonical revision instead of
    // activating a historical ciphertext in place.
    pub fn restore_version(&mut self, id: &str, at: &str) -> Result<()> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        // A trashed item restored to an old version would come back live with
        // that value in one step, skipping the restore that says it is back.
        if item.get("state").and_then(Value::as_str) == Some("trashed") {
            bail!("item is in trash: {id}; `skarbiec restore {id}` brings it back first, then `skarbiec restore {id} --at {at}` picks the version");
        }
        let envelope_kind = item
            .get("kind")
            .and_then(Value::as_str)
            .context("canonical item has no kind")?
            .to_string();
        let history = super::stored_history(id, item)?;
        let Some(chosen) = history
            .iter()
            .find(|version| version.get("created_at").and_then(Value::as_str) == Some(at))
        else {
            // The stamps that do exist, so the caller can pick one instead of
            // guessing the shape of the one that did not match.
            let stamps: Vec<&str> = history
                .iter()
                .filter_map(|version| version.get("created_at").and_then(Value::as_str))
                .collect();
            if stamps.is_empty() {
                bail!("no version at {at} for {id}: {id} keeps no earlier version, only its current value");
            }
            bail!(
                "no version at {at} for {id}; its saved versions are at: {} (`skarbiec history {id}` lists them)",
                stamps.join(", ")
            );
        };
        // A revision recorded before revisions carried their own kind has the item's kind.
        let kind = match chosen.get("kind").and_then(Value::as_str) {
            Some(kind) => kind.to_string(),
            None => envelope_kind,
        };
        let cipher = chosen
            .get("ciphertext")
            .and_then(Value::as_str)
            .context("historical revision missing ciphertext")?;
        let plain = crypto::decrypt(cipher)?;
        let payload: Value =
            serde_json::from_str(&plain).context("historical revision is not JSON")?;
        schema::validate_payload(&payload, &kind)?;
        let recipients = self.item_recipient_uids(id)?;
        let tags = crate::core::vault::entry_texts(id, item, "tags")?;
        self.set_item(id, &kind, &payload, &recipients, &tags)
    }

    /// Every revision the item keeps, oldest first, then the current one, as
    /// metadata: what `restore <id> --at <at>` can bring back.
    ///
    /// Each entry carries the stamp `--at` takes (`at`), its revision and
    /// kind, who wrote it and under which lifecycle operation, and whether it
    /// is the current value. A version written before revisions carried their
    /// own number or kind reports null for it. Nothing is decrypted, so the
    /// answer comes even from a host whose GnuPG cannot open the item.
    pub fn versions(&self, id: &str) -> Result<Value> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        let describe = |version: &Value, current: bool| {
            json!({
                "at": version.get("created_at"),
                "revision": version.get("revision"),
                "kind": version.get("kind"),
                "written_by": version.get("written_by"),
                "operation_id": version.get("operation_id"),
                "current": current,
            })
        };
        let mut versions: Vec<Value> = super::stored_history(id, item)?
            .iter()
            .map(|version| describe(version, false))
            .collect();
        if let Some(current) = item.get("current") {
            versions.push(describe(current, true));
        }
        Ok(json!({
            "id": id,
            "item_uid": item.get("item_uid"),
            "state": item.get("state"),
            "revision": item.get("revision"),
            "versions": versions,
        }))
    }

    /// `history <id> --changes`: for each saved version after the first,
    /// which field names it added, removed or changed against the version
    /// before it. Every version is decrypted to compare, and only names leave
    /// this function: no value, length or digest. A version that will not
    /// open is named with its error, and the comparison skips past it rather
    /// than reporting a change that was never seen.
    pub fn version_changes(&self, id: &str) -> Result<Value> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        let mut ordered = super::stored_history(id, item)?;
        if let Some(current) = item.get("current") {
            ordered.push(current.clone());
        }
        let mut changes = Vec::new();
        let mut previous: Option<serde_json::Map<String, Value>> = None;
        for version in &ordered {
            let at = version.get("created_at").cloned();
            let opened = version
                .get("ciphertext")
                .and_then(Value::as_str)
                .context("saved version has no ciphertext")
                .and_then(crypto::decrypt)
                .and_then(|plain| {
                    serde_json::from_str::<Value>(&plain).context("saved version is not JSON")
                });
            let fields = match opened {
                Ok(payload) => match payload.get("fields").and_then(Value::as_object) {
                    Some(fields) => fields.clone(),
                    None => {
                        changes.push(json!({"at": at, "error": "the saved version holds no fields object"}));
                        continue;
                    }
                },
                Err(error) => {
                    changes.push(json!({"at": at, "error": format!("{error:#}")}));
                    continue;
                }
            };
            if let Some(before) = &previous {
                let added: Vec<&String> = fields.keys().filter(|name| !before.contains_key(*name)).collect();
                let removed: Vec<&String> = before.keys().filter(|name| !fields.contains_key(*name)).collect();
                let changed: Vec<&String> = fields
                    .iter()
                    .filter(|(name, value)| before.get(*name).is_some_and(|old| old != *value))
                    .map(|(name, _)| name)
                    .collect();
                changes.push(json!({"at": at, "added": added, "removed": removed, "changed": changed}));
            }
            previous = Some(fields);
        }
        Ok(json!({"id": id, "changes": changes}))
    }
}
