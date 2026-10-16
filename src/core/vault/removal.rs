// Removing one person from the whole vault. `revoke` narrows one item; a
// person who leaves has to lose every item at once, including the historical
// revisions and the trashed items a restore would bring back, and nothing a
// later `share` or emergency activation could hand back to them may survive.

use anyhow::{bail, Result};
use serde_json::{json, Value};

use super::{obj_mut, Vault};

impl Vault {
    /// Drop `uid` from every item it can read and from the recipient registry.
    ///
    /// Every current and historical ciphertext of those items is re-encrypted
    /// to the remaining recipients plus the owner and recovery keys, the
    /// registry entry is deleted so a later `share` refuses the uid until it is
    /// added again, and a pending emergency grant for the uid is cancelled.
    /// Nothing reaches disk until every rewrap has succeeded.
    ///
    /// Re-encryption stops future reads from the vault; it cannot take back a
    /// value the person already read. The report therefore names every item
    /// they could open, so those values can be rotated.
    pub fn remove_recipient(&mut self, uid: &str) -> Result<Value> {
        if uid == self.owner_uid() {
            bail!(
                "{uid} is the vault owner; install another owner with rotate-owner first, then remove {uid}"
            );
        }
        let Some(fingerprint) = self.recipient_fpr(uid) else {
            bail!("unknown recipient: {uid}");
        };
        if fingerprint == self.recovery_fpr() {
            bail!("{uid} holds the recovery key; the recovery recipient cannot be removed");
        }
        // Which items a leaving recipient can read comes from each item's
        // stored list. One that is not a list of text is refused first: read
        // as no recipients, the item was never rewrapped and the removed
        // recipient kept reading it.
        let held: Vec<String> = self
            .doc
            .get("items")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(id, _)| id.clone())
            .collect();
        for id in &held {
            self.item_recipient_uids(id)?;
        }
        // Each exposed item with the state it records; one that records none
        // is reported as such, since the vault reads an item without a state
        // as not active everywhere else.
        let exposed: Vec<(String, Option<String>)> = self
            .doc
            .get("items")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter(|(_, item)| {
                item.get("recipients")
                    .and_then(Value::as_array)
                    .is_some_and(|uids| uids.iter().any(|entry| entry.as_str() == Some(uid)))
            })
            .map(|(id, item)| {
                let state = item
                    .get("state")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                (id.clone(), state)
            })
            .collect();
        // The historical versions rewrapped, summed over every exposed item.
        let versions = exposed
            .iter()
            .map(|(id, _)| -> Result<usize> {
                let remaining: Vec<String> = self
                    .item_recipient_uids(id)?
                    .into_iter()
                    .filter(|entry| entry != uid)
                    .collect();
                self.rewrap_item(id, &remaining)
            })
            .sum::<Result<usize>>()?;
        obj_mut(&mut self.doc, "recipients").remove(uid);
        let emergency_cancelled = self
            .doc
            .get_mut("emergency")
            .and_then(Value::as_object_mut)
            .and_then(|grants| grants.remove(uid))
            .is_some();
        self.save()?;
        Ok(json!({
            "ok": true,
            "uid": uid,
            "fingerprint": fingerprint,
            "items_rewrapped": exposed.len(),
            "historical_versions": versions,
            "emergency_grant_cancelled": emergency_cancelled,
            "exposed": exposed
                .iter()
                .map(|(id, state)| json!({"item": id, "state": state}))
                .collect::<Vec<Value>>(),
        }))
    }
}
