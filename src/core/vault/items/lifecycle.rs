// Reading an item, listing what the vault holds, and the states between in
// use and gone: trash, reclaim, restore and purge.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

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
