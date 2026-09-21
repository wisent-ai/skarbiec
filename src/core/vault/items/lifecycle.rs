// Reading an item, listing what the vault holds, and the states between in
// use and gone: trash, reclaim, restore and purge.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::core::vault::items::duplicates;
use crate::core::vault::{current_envelope, now, obj_mut, Vault};
use crate::core::{crypto, schema};

impl Vault {
    pub fn get_item(&self, id: &str) -> Result<Value> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        if item.get("format").and_then(Value::as_u64) != Some(current_envelope()) {
            bail!("item uses the legacy envelope: {id} (run migrate-v2)");
        }
        if item.get("state").and_then(Value::as_str) == Some("trashed") {
            bail!("item is in trash: {id} (restore it first)");
        }
        let kind = item
            .get("kind")
            .and_then(Value::as_str)
            .context("canonical item has no kind")?;
        let cipher = item
            .get("current")
            .and_then(|current| current.get("ciphertext"))
            .and_then(Value::as_str)
            .context("canonical item has no current ciphertext")?;
        let plain = crypto::decrypt(cipher)?;
        let payload: Value = serde_json::from_str(&plain).context("decrypted item is not JSON")?;
        schema::validate_payload(&payload, kind)?;
        Ok(payload)
    }

    /// Every set of active items that hold exactly the same payload.
    ///
    /// Answered from the cleartext envelope, so it decrypts nothing and works
    /// on a host whose GnuPG is the fault. Each group carries the ids and the
    /// kind they share; the fingerprint itself stays inside the vault, because
    /// it is a digest of secret content.
    pub fn duplicate_groups(&self) -> Vec<Value> {
        let Some(items) = self.doc.get("items").and_then(Value::as_object) else {
            return Vec::new();
        };
        duplicates::groups(items)
            .into_iter()
            .map(|(_, ids)| {
                let kind = ids
                    .first()
                    .and_then(|id| items.get(id))
                    .and_then(|entry| entry.get("kind"))
                    .cloned()
                    .unwrap_or(Value::Null);
                json!({"kind": kind, "items": ids})
            })
            .collect()
    }

    /// How much of the vault the duplicate answer covers: active items, and
    /// how many of them carry no payload fingerprint yet.
    ///
    /// An item written before 0.3.11 has no fingerprint, so it cannot be
    /// compared with anything and an empty duplicate report over such a vault
    /// means "nothing comparable", not "no duplicates". Saying so is the
    /// difference between a report and a reassurance: on this fleet the vault
    /// held 66 login rows, 29 of them describing 12 platforms, and every one
    /// of them predates the fingerprint.
    pub fn duplicate_coverage(&self) -> (usize, usize) {
        let Some(items) = self.doc.get("items").and_then(Value::as_object) else {
            return (0, 0);
        };
        let active: Vec<&Value> = items
            .values()
            .filter(|entry| entry.get("state").and_then(Value::as_str) == Some("active"))
            .collect();
        let unstamped = active
            .iter()
            .filter(|entry| entry.get(duplicates::FINGERPRINT_KEY).is_none())
            .count();
        (active.len(), unstamped)
    }

    /// Stamps the payload fingerprint onto every active item that has none,
    /// so the duplicate report and the write refusal cover the whole vault
    /// rather than only what was written after 0.3.11.
    ///
    /// Reads each item through the same decrypt-and-validate path `get_item`
    /// uses. `apply` false reports what the pass would do and writes nothing.
    /// The ciphertext, revision and history are untouched: the payload is
    /// described, not rewritten, so no item gains a revision and no recipient
    /// list changes.
    pub fn stamp_fingerprints(&mut self, apply: bool) -> Result<Value> {
        // A vault written before 0.3.11 carries no salt, and minting one is
        // part of this pass rather than a reason to refuse it: the salt is
        // what the fingerprints are taken under, and an existing one always
        // wins, so a second pass never unlinks the first one's work.
        self.ensure_fingerprint_salt()?;
        let salt = self
            .doc
            .get(duplicates::SALT_KEY)
            .and_then(Value::as_str)
            .context("the vault has no fingerprint salt even after minting one")?
            .to_string();
        let items = self
            .doc
            .get("items")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let planned = duplicates::stamp::plan(&items, &salt, |id| self.get_item(id));
        let report = planned.report(apply);
        if !apply || planned.prints.is_empty() {
            return Ok(report);
        }
        let stored = self
            .doc
            .get_mut("items")
            .and_then(Value::as_object_mut)
            .context("vault document carries no items object")?;
        for (id, print) in &planned.prints {
            let entry = stored
                .get_mut(id)
                .and_then(Value::as_object_mut)
                .with_context(|| format!("{id} left the vault during the pass"))?;
            entry.insert(
                duplicates::FINGERPRINT_KEY.to_string(),
                Value::String(print.clone()),
            );
        }
        self.save()?;
        Ok(report)
    }

    pub fn list(&self, include_deleted: bool) -> Vec<Value> {
        self.doc
            .get("items")
            .and_then(Value::as_object)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|(id, item)| {
                        let state = item
                            .get("state")
                            .and_then(Value::as_str)
                            .unwrap_or("legacy");
                        let deleted = state == "trashed";
                        if deleted && !include_deleted {
                            return None;
                        }
                        let history_len = item
                            .get("history")
                            .and_then(Value::as_array)
                            .map(Vec::len)
                            .unwrap_or_default();
                        let versions = history_len.saturating_add(std::iter::once(()).count());
                        Some(json!({
                            "id": id,
                            // `null` for an item that predates the field, the
                            // same way this projection already reports a
                            // missing `kind`. That null is useful rather than
                            // untidy: it is how an operator sees which items
                            // `backfill-item-uids` still has to stamp.
                            "item_uid": item.get("item_uid"),
                            "kind": item.get("kind"),
                            "state": state,
                            "revision": item.get("revision"),
                            "management": item.get("management"),
                            "tags": item.get("tags"),
                            "recipients": item.get("recipients"),
                            "updated_at": item.get("updated_at"),
                            "deleted": deleted,
                            "versions": versions,
                        }))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    // Trash is recoverable. Purge remains a separate owner-only operation.
    pub fn delete_item(&mut self, id: &str) -> Result<()> {
        let stamp = now();
        let entry = obj_mut(&mut self.doc, "items")
            .get_mut(id)
            .and_then(Value::as_object_mut)
            .with_context(|| format!("no item: {id}"))?;
        entry.insert("state".to_string(), json!("trashed"));
        entry.insert("updated_at".to_string(), json!(stamp));
        self.save()
    }

    /// Return one item to owner control.
    ///
    /// `management` is written from the identity of whoever first wrote the
    /// item, and afterwards only that authority may change it. A consumer that
    /// wrote through an API the broker no longer serves therefore leaves the
    /// item with **no writer at all**: the owner is refused as "not
    /// owner-controlled", and the consumer's own path is gone. Three fleet SSH
    /// host keys reached exactly that state, and a key that cannot be rotated
    /// cannot be revoked either.
    ///
    /// Reclaiming is deliberately narrow. It moves control and touches nothing
    /// else - no field, tag, recipient or revision changes - so the material
    /// stays exactly as the previous controller left it, and the next ordinary
    /// owner write is what changes anything. Items under the Weles credential
    /// lifecycle are refused: their local state must not diverge from the
    /// provider's, which is the guarantee that mode exists to make.
    pub fn reclaim_item(&mut self, id: &str) -> Result<()> {
        let entry = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        let management = entry
            .get("management")
            .and_then(Value::as_object)
            .context("item has no canonical management metadata")?;
        let mode = management
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if mode == "managed" {
            bail!("{id} is under the credential lifecycle; use a credential operation");
        }
        if entry
            .get("tags")
            .and_then(Value::as_array)
            .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some("managed:weles")))
        {
            bail!("{id} is managed by Weles; use a credential operation");
        }
        let owner = self.owner_uid().to_string();
        if mode == "owner" && management.get("controller").and_then(Value::as_str) == Some(&owner) {
            return Ok(());
        }
        let previous = management
            .get("controller")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let stamp = now();
        let entry = obj_mut(&mut self.doc, "items")
            .get_mut(id)
            .and_then(Value::as_object_mut)
            .with_context(|| format!("no item: {id}"))?;
        entry.insert(
            "management".to_string(),
            json!({"mode": "owner", "controller": owner}),
        );
        entry.insert("updated_at".to_string(), json!(stamp));
        self.save()?;
        crate::runtime::audit::append(
            "item-reclaimed",
            &json!({"item": id, "previous_controller": previous, "previous_mode": mode}),
        )
    }

    pub fn restore_item(&mut self, id: &str) -> Result<()> {
        let stamp = now();
        let entry = obj_mut(&mut self.doc, "items")
            .get_mut(id)
            .and_then(Value::as_object_mut)
            .with_context(|| format!("no item: {id}"))?;
        entry.insert("state".to_string(), json!("active"));
        entry.insert("updated_at".to_string(), json!(stamp));
        self.save()
    }

    pub fn purge_item(&mut self, id: &str) -> Result<()> {
        obj_mut(&mut self.doc, "items")
            .remove(id)
            .with_context(|| format!("no item: {id}"))?;
        self.save()
    }
}
