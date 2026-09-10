// Who an item is encrypted to: registering recipients, resolving their
// fingerprints, re-wrapping ciphertext, and moving ownership.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use super::{current_envelope, now, obj_mut, Vault};
use crate::core::crypto;

impl Vault {
    pub fn ensure_owner_controlled(&self, id: &str) -> Result<()> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("item not found: {id}"))?;
        let management = item
            .get("management")
            .and_then(Value::as_object)
            .context("item has no canonical management metadata")?;
        if management.get("mode").and_then(Value::as_str) != Some("owner")
            || management.get("controller").and_then(Value::as_str) != Some(self.owner_uid())
        {
            bail!("{id} is not owner-controlled");
        }
        Ok(())
    }

    pub fn recipient_fpr(&self, uid: &str) -> Option<String> {
        self.doc
            .get("recipients")?
            .get(uid)?
            .get("fingerprint")?
            .as_str()
            .map(str::to_string)
    }

    pub fn register_recipient(&mut self, uid: &str, fingerprint: &str, role: &str) -> Result<()> {
        let stamp = now();
        obj_mut(&mut self.doc, "recipients").insert(
            uid.to_string(),
            json!({"fingerprint": fingerprint, "role": role, "added_at": stamp}),
        );
        self.save()
    }

    // Fingerprints an item must be encrypted to: its shared recipients plus the
    // always-present owner and recovery keys. Unknown uids are skipped (they
    // must be registered first).
    pub(in crate::core::vault) fn fprs_for(&self, recipient_uids: &[String]) -> Vec<String> {
        let mut fprs = Vec::new();
        let mut want: Vec<String> = recipient_uids.to_vec();
        want.push(self.owner_uid().to_string());
        for uid in want {
            if let Some(fpr) = self.recipient_fpr(&uid) {
                if !fprs.contains(&fpr) {
                    fprs.push(fpr);
                }
            }
        }
        let recovery = self.recovery_fpr().to_string();
        if !recovery.is_empty() && !fprs.contains(&recovery) {
            fprs.push(recovery);
        }
        fprs
    }

    // Decrypt then re-encrypt one ciphertext onto a new recipient set. The
    // plaintext lives only for this call.
    fn rewrap(fprs: &[String], ciphertext: &str) -> Result<String> {
        let plain = crypto::decrypt(ciphertext)?;
        crypto::encrypt_to(fprs, &plain)
    }

    /// Install a new owner across the entire vault.
    ///
    /// Registering an owner is not the same as installing one: the stored
    /// ciphertext stays encrypted to the previous owner's key, so a freshly
    /// registered owner can open nothing while every read still succeeds for
    /// whoever holds the old key. If that key then goes missing, the vault is
    /// unreadable by everyone. This rotates for real — every current and
    /// historical ciphertext is rewrapped onto the new recipient set, which
    /// `fprs_for` derives from the updated owner plus the recovery key, so the
    /// recovery recipient survives untouched.
    ///
    /// The previous owner is dropped from every item and keeps only its
    /// registry entry, demoted: the fingerprint stays on record, the access
    /// does not.
    ///
    /// Nothing reaches disk until every ciphertext has been rewrapped, so the
    /// old key (or the recovery key) must be in the keyring first. A failure
    /// part-way leaves the vault file exactly as it was rather than encrypted
    /// to two owners at once.
    pub fn rotate_owner(&mut self, new_owner_uid: &str, new_owner_fpr: &str) -> Result<Value> {
        let previous = self.owner_uid().to_string();
        if previous == new_owner_uid {
            bail!("{new_owner_uid} is already the owner");
        }
        let stamp = now();
        let recipients = obj_mut(&mut self.doc, "recipients");
        recipients.insert(
            new_owner_uid.to_string(),
            json!({"fingerprint": new_owner_fpr, "role": "owner", "added_at": stamp}),
        );
        if let Some(entry) = recipients.get_mut(&previous).and_then(Value::as_object_mut) {
            entry.insert("role".to_string(), json!("member"));
            entry.insert("owner_until".to_string(), json!(stamp));
        }
        self.doc
            .as_object_mut()
            .context("vault document is not an object")?
            .insert("owner".to_string(), json!(new_owner_uid));

        // Deleted items still hold secrets and are still restorable, so they
        // rotate too.
        let ids: Vec<String> = self
            .doc
            .get("items")
            .and_then(Value::as_object)
            .map(|items| items.keys().cloned().collect())
            .unwrap_or_default();
        let mut versions = usize::default();
        for id in &ids {
            let uids: Vec<String> = self
                .item_recipient_uids(id)
                .into_iter()
                .filter(|uid| uid != &previous)
                .collect();
            let fprs = self.fprs_for(&uids);
            let item = self
                .doc
                .get("items")
                .and_then(|items| items.get(id))
                .with_context(|| format!("no item: {id}"))?;
            if item.get("format").and_then(Value::as_u64) != Some(current_envelope()) {
                bail!("{id} uses a legacy envelope; run migrate-v2 before rotating the owner");
            }
            let mut current = item
                .get("current")
                .and_then(Value::as_object)
                .cloned()
                .with_context(|| format!("item has no current revision: {id}"))?;
            let current_cipher = current
                .get("ciphertext")
                .and_then(Value::as_str)
                .with_context(|| format!("item has no current ciphertext: {id}"))?;
            let rotated_current = Self::rewrap(&fprs, current_cipher)
                .with_context(|| format!("rewrap current ciphertext: {id}"))?;
            current.insert("ciphertext".to_string(), json!(rotated_current));
            let history = item
                .get("history")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut rotated_history = Vec::new();
            for version in history {
                let mut version = version
                    .as_object()
                    .cloned()
                    .with_context(|| format!("historical revision is not an object: {id}"))?;
                let cipher = version
                    .get("ciphertext")
                    .and_then(Value::as_str)
                    .with_context(|| format!("historical revision has no ciphertext: {id}"))?;
                let rotated = Self::rewrap(&fprs, cipher)
                    .with_context(|| format!("rewrap historical ciphertext: {id}"))?;
                version.insert("ciphertext".to_string(), json!(rotated));
                rotated_history.push(Value::Object(version));
            }
            versions = versions.saturating_add(rotated_history.len());

            let entry = obj_mut(&mut self.doc, "items")
                .get_mut(id)
                .and_then(Value::as_object_mut)
                .with_context(|| format!("no item: {id}"))?;
            entry.insert("current".to_string(), Value::Object(current));
            entry.insert("history".to_string(), json!(rotated_history));
            entry.insert("recipients".to_string(), json!(uids));
        }
        self.save()?;
        Ok(json!({
            "ok": true,
            "owner": new_owner_uid,
            "fingerprint": new_owner_fpr,
            "previous_owner": previous,
            "items": ids.len(),
            "historical_versions": versions,
            "recovery_preserved": !self.recovery_fpr().is_empty(),
        }))
    }

    pub fn item_recipient_uids(&self, id: &str) -> Vec<String> {
        self.doc
            .get("items")
            .and_then(|m| m.get(id))
            .and_then(|it| it.get("recipients"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }
}
