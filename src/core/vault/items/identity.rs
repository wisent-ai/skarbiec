// The identity a rename cannot touch: resolving an item_uid back to the id
// that holds it, renaming, backfilling missing uids, and restoring a version.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::core::vault::{
    current_envelope, entry_item_uid, mint_item_uid, now, obj_mut, Vault,
};
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

    /// Move one item to a new id, keeping everything that is not the id.
    ///
    /// The entry object is moved whole, so `item_uid`, history, revision,
    /// created_at, tags, recipients, management and the ciphertext itself are
    /// the same bytes at the new key. Nothing is decrypted or re-encrypted:
    /// the id is a map key, not part of the sealed payload.
    ///
    /// Improvising this with `get` + `set-json` under a new id + `delete` does
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
        if !schema::exact_token(to, schema::MAX_NAME_CHARS) {
            bail!("a new item id must be one exact name of 1 to {} characters with no NUL, newline or carriage return", schema::MAX_NAME_CHARS);
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
            bail!("{from} still uses the legacy envelope; run migrate-v2 before renaming it");
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
        let items = obj_mut(&mut self.doc, "items");
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
        let ids: Vec<String> = self
            .doc
            .get("items")
            .and_then(Value::as_object)
            .map(|items| {
                items
                    .iter()
                    .filter(|(_, entry)| entry_item_uid(entry).is_none())
                    .map(|(id, _)| id.clone())
                    .collect()
            })
            .unwrap_or_default();
        let total = self
            .doc
            .get("items")
            .and_then(Value::as_object)
            .map(Map::len)
            .unwrap_or_default();
        if ids.is_empty() {
            return Ok((ids, total));
        }
        for id in &ids {
            let minted = mint_item_uid()?;
            let entry = obj_mut(&mut self.doc, "items")
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
        let envelope_kind = item
            .get("kind")
            .and_then(Value::as_str)
            .context("canonical item has no kind")?
            .to_string();
        let chosen = item
            .get("history")
            .and_then(Value::as_array)
            .and_then(|history| {
                history
                    .iter()
                    .find(|version| version.get("created_at").and_then(Value::as_str) == Some(at))
            })
            .with_context(|| format!("no version at {at} for {id}"))?;
        let kind = chosen
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or(&envelope_kind)
            .to_string();
        let cipher = chosen
            .get("ciphertext")
            .and_then(Value::as_str)
            .context("historical revision missing ciphertext")?;
        let plain = crypto::decrypt(cipher)?;
        let payload: Value =
            serde_json::from_str(&plain).context("historical revision is not JSON")?;
        schema::validate_payload(&payload, &kind)?;
        let recipients = self.item_recipient_uids(id);
        let tags: Vec<String> = item
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
        self.set_item(id, &kind, &payload, &recipients, &tags)
    }
}
