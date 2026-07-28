// Encrypted per-recipient vault document for skarbiec. Every item is gpg-armored
// ciphertext encrypted to the public keys of its recipients (always the owner
// and the recovery key, plus anyone it is shared with). The on-disk file is an
// index of that ciphertext plus non-secret metadata — safe at rest.
//
// All numbers enter at runtime (argv / stored JSON written by the compiled
// binary), never as literals in this source.

use anyhow::{bail, Context, Result};
use rand::RngCore;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::Zeroize;

use crate::core::crypto;

const APPLE_CHALLENGE_PREFIX: &str = "challenge:apple/";

pub(crate) fn is_apple_challenge_resource(resource: &str) -> bool {
    let Some(uuid) = resource.strip_prefix(APPLE_CHALLENGE_PREFIX) else {
        return false;
    };
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn valid_apple_challenge_scalar(value: &Value) -> bool {
    value.as_object().is_some_and(|fields| fields.len() == 2)
        && value.get("type").and_then(Value::as_str) == Some("apple-challenge")
        && value
            .get("value")
            .and_then(Value::as_str)
            .is_some_and(|code| code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()))
}

fn zeroize_json_strings(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json_strings),
        Value::Object(values) => values.values_mut().for_each(zeroize_json_strings),
        _ => {}
    }
}

fn lock_vault_parent(path: &Path) -> Result<File> {
    let parent = path.parent().context("vault path has no parent")?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?;
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error()).context("lock vault parent");
    }
    Ok(directory)
}

pub struct Vault {
    pub path: PathBuf,
    doc: Value,
    _lock: File,
}

pub struct OwnerRotationReport {
    pub items: usize,
    pub versions: usize,
    pub old_fingerprint: String,
    pub new_fingerprint: String,
}

fn push_unique_fingerprint(fingerprints: &mut Vec<String>, fingerprint: &str) {
    if !fingerprints
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(fingerprint))
    {
        fingerprints.push(fingerprint.to_string());
    }
}

fn rewrap_ciphertext(ciphertext: &str, fingerprints: &[String]) -> Result<String> {
    let mut plaintext = crypto::decrypt(ciphertext)?;
    let encrypted = crypto::encrypt_to(fingerprints, &plaintext);
    plaintext.zeroize();
    encrypted
}

fn obj_mut<'a>(v: &'a mut Value, key: &str) -> &'a mut Map<String, Value> {
    v.get_mut(key)
        .and_then(Value::as_object_mut)
        .expect("vault section is an object")
}

fn now() -> String {
    // ISO-8601 via `date` — avoids a numeric time literal and needs no crate.
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

impl Vault {
    pub fn create(
        path: PathBuf,
        owner_uid: &str,
        owner_fpr: &str,
        recovery_fpr: &str,
    ) -> Result<Self> {
        let lock = lock_vault_parent(&path)?;
        if path.exists() {
            bail!("vault already exists at {}", path.display());
        }
        let doc = json!({
            "version": "v1",
            "owner": owner_uid,
            "recovery": recovery_fpr,
            "recipients": { owner_uid: {"fingerprint": owner_fpr, "role": "owner", "added_at": now()} },
            "items": {},
            "tokens": {},
            "policy": {},
        });
        let vault = Self {
            path,
            doc,
            _lock: lock,
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn open(path: PathBuf) -> Result<Self> {
        let lock = lock_vault_parent(&path)?;
        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("vault not initialized at {} (run: init)", path.display()))?;
        if meta.file_type().is_symlink()
            || !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.permissions().mode() & 0o077 != 0
        {
            bail!("vault path must be an owner-only regular file");
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        let mut body = String::new();
        file.read_to_string(&mut body)?;
        let doc = serde_json::from_str(&body).context("parse vault file")?;
        Ok(Self {
            path,
            doc,
            _lock: lock,
        })
    }

    pub fn save(&self) -> Result<()> {
        let parent = self.path.parent().context("vault path has no parent")?;
        let mut suffix = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut suffix);
        let temp = parent.join(format!(
            ".skarbiec-vault-{}",
            suffix
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        file.write_all(serde_json::to_string_pretty(&self.doc)?.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, &self.path)?;
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(parent)?
            .sync_all()?;
        Ok(())
    }

    pub fn doc(&self) -> &Value {
        &self.doc
    }

    /// Mutable access to the vault document for sibling layers (tokens, policy,
    /// recovery, audit metadata) that own their own top-level section. Callers
    /// must `save()` after mutating.
    pub fn doc_mut(&mut self) -> &mut Value {
        &mut self.doc
    }

    pub fn owner_uid(&self) -> &str {
        self.doc.get("owner").and_then(Value::as_str).unwrap_or("")
    }

    pub fn recovery_fpr(&self) -> &str {
        self.doc
            .get("recovery")
            .and_then(Value::as_str)
            .unwrap_or("")
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
    fn fprs_for(&self, recipient_uids: &[String]) -> Vec<String> {
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

    pub fn contains_item(&self, id: &str) -> bool {
        self.doc
            .get("items")
            .and_then(Value::as_object)
            .is_some_and(|items| items.contains_key(id))
    }

    // Store (or replace) a secret. Encrypts to the given recipients; the prior
    // ciphertext is pushed onto the version history.
    fn set_item_inner(
        &mut self,
        id: &str,
        item_type: &str,
        secret: &Value,
        recipient_uids: &[String],
        tags: &[String],
    ) -> Result<()> {
        let fprs = self.fprs_for(recipient_uids);
        let mut plaintext = serde_json::to_string(secret)?;
        let encrypted = crypto::encrypt_to(&fprs, &plaintext);
        plaintext.zeroize();
        let cipher = encrypted?;
        let stamp = now();
        let items = obj_mut(&mut self.doc, "items");
        let history = match items.get(id) {
            Some(prev) => {
                let mut h = prev
                    .get("history")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if let (Some(at), Some(c)) = (prev.get("updated_at"), prev.get("current")) {
                    h.push(json!({"at": at, "cipher": c}));
                }
                h
            }
            None => Vec::new(),
        };
        let created = items
            .get(id)
            .and_then(|p| p.get("created_at"))
            .cloned()
            .unwrap_or_else(|| json!(stamp));
        items.insert(
            id.to_string(),
            json!({
                "type": item_type,
                "created_at": created,
                "updated_at": stamp,
                "recipients": recipient_uids,
                "tags": tags,
                "current": cipher,
                "history": history,
                "deleted": false,
                "deleted_at": Value::Null,
            }),
        );
        self.save()
    }

    pub fn set_item(
        &mut self,
        id: &str,
        item_type: &str,
        secret: &Value,
        recipient_uids: &[String],
        tags: &[String],
    ) -> Result<()> {
        if id.starts_with("challenge:apple/") {
            bail!("Apple challenges may only be stored with apple-challenge-put over stdin");
        }
        self.set_item_inner(id, item_type, secret, recipient_uids, tags)
    }

    pub(crate) fn put_apple_challenge(&mut self, id: &str, secret: &Value) -> Result<()> {
        if !is_apple_challenge_resource(id) || !valid_apple_challenge_scalar(secret) {
            bail!("invalid dedicated Apple challenge scalar");
        }
        if self.contains_item(id) {
            bail!("refusing to overwrite existing vault item: {id}");
        }
        self.set_item_inner(id, "apple-challenge", secret, &[], &[])
    }

    fn get_item_inner(&self, id: &str) -> Result<Value> {
        let item = self
            .doc
            .get("items")
            .and_then(|m| m.get(id))
            .with_context(|| format!("no item: {id}"))?;
        if item
            .get("deleted")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            bail!("item is in trash: {id} (restore it first)");
        }
        let cipher = item
            .get("current")
            .and_then(Value::as_str)
            .context("item has no ciphertext")?;
        let mut plain = crypto::decrypt(cipher)?;
        let parsed = serde_json::from_str(&plain).context("decrypted item is not JSON");
        plain.zeroize();
        parsed
    }

    pub fn get_item(&self, id: &str) -> Result<Value> {
        if id.starts_with("challenge:apple/") {
            bail!("Apple challenges may only be read through capability redemption");
        }
        self.get_item_inner(id)
    }

    pub(crate) fn take_apple_challenge(&mut self, id: &str) -> Result<Option<Value>> {
        if !is_apple_challenge_resource(id) {
            bail!("invalid Apple challenge resource");
        }
        if !self.contains_item(id) {
            return Ok(None);
        }
        let mut value = self.get_item_inner(id)?;
        if !valid_apple_challenge_scalar(&value) {
            zeroize_json_strings(&mut value);
            bail!("Apple challenge is not a dedicated six-digit scalar");
        }
        if let Err(error) = self.purge_item(id) {
            zeroize_json_strings(&mut value);
            return Err(error);
        }
        Ok(Some(value))
    }

    pub(crate) fn purge_apple_challenge(&mut self, id: &str) -> Result<()> {
        if !is_apple_challenge_resource(id) {
            bail!("invalid Apple challenge resource");
        }
        if self.contains_item(id) {
            self.purge_item(id)?;
        }
        Ok(())
    }

    pub fn list(&self, include_deleted: bool) -> Vec<Value> {
        self.doc
            .get("items")
            .and_then(Value::as_object)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|(id, it)| {
                        let deleted = it.get("deleted").and_then(Value::as_bool).unwrap_or(false);
                        if deleted && !include_deleted {
                            return None;
                        }
                        let history_len = it
                            .get("history")
                            .and_then(Value::as_array)
                            .map(|h| h.len())
                            .unwrap_or_default();
                        let versions = history_len + std::iter::once(()).count(); // history + the current version
                        Some(json!({
                            "id": id,
                            "type": it.get("type"),
                            "tags": it.get("tags"),
                            "updated_at": it.get("updated_at"),
                            "deleted": deleted,
                            "versions": versions,
                        }))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Re-encrypt every current and historical item version to a replacement
    /// automatic owner while retaining recovery and explicit shared recipients.
    ///
    /// All work is performed against a cloned document. The live document is
    /// swapped only for the single atomic save and restored in memory if that
    /// save fails, so a decrypt or encrypt failure cannot partially migrate the
    /// vault.
    pub fn rotate_owner(
        &mut self,
        new_owner_uid: &str,
        new_owner_fingerprint: &str,
    ) -> Result<OwnerRotationReport> {
        let old_owner_uid = self.owner_uid().to_string();
        if old_owner_uid.is_empty() {
            bail!("vault owner metadata is empty");
        }
        if old_owner_uid == new_owner_uid {
            bail!("new owner UID must differ from the current owner UID");
        }
        let old_owner_fingerprint = self
            .recipient_fpr(&old_owner_uid)
            .context("current owner has no recipient fingerprint")?;
        if old_owner_fingerprint.is_empty()
            || !old_owner_fingerprint
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            bail!("current owner fingerprint is invalid");
        }
        if old_owner_fingerprint.eq_ignore_ascii_case(new_owner_fingerprint) {
            bail!("new owner fingerprint matches the current owner fingerprint");
        }
        if new_owner_fingerprint.is_empty()
            || !new_owner_fingerprint
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            bail!("new owner fingerprint is invalid");
        }
        let recovery_fingerprint = self.recovery_fpr().to_string();
        if recovery_fingerprint.trim().is_empty() {
            bail!("vault recovery fingerprint is empty");
        }
        if recovery_fingerprint.eq_ignore_ascii_case(&old_owner_fingerprint) {
            bail!("recovery fingerprint matches the current owner fingerprint");
        }
        if recovery_fingerprint.eq_ignore_ascii_case(new_owner_fingerprint) {
            bail!("new owner fingerprint matches the recovery fingerprint");
        }
        if !crypto::public_key_exists(&old_owner_fingerprint)? {
            bail!("current owner public key is missing");
        }
        if !crypto::public_key_exists(new_owner_fingerprint)? {
            bail!("new owner public key is missing");
        }
        if !crypto::public_key_exists(&recovery_fingerprint)? {
            bail!("recovery public key is missing");
        }

        let recipient_metadata = self
            .doc
            .get("recipients")
            .and_then(Value::as_object)
            .context("vault recipients metadata is not an object")?;
        let mut recipient_fingerprints = HashMap::new();
        for (uid, metadata) in recipient_metadata {
            if let Some(fingerprint) = metadata.get("fingerprint").and_then(Value::as_str) {
                if !fingerprint.is_empty() {
                    recipient_fingerprints.insert(uid.clone(), fingerprint.to_string());
                }
            }
        }

        let mut staged = self.doc.clone();
        let items = staged
            .get_mut("items")
            .and_then(Value::as_object_mut)
            .context("vault items section is not an object")?;
        let mut item_count = usize::default();
        let mut version_count = usize::default();
        let mut checked_shared_fingerprints = HashSet::new();
        for (id, item) in items {
            let entry = item
                .as_object_mut()
                .with_context(|| format!("vault item is not an object: {id}"))?;
            let stored_recipient_uids = entry
                .get("recipients")
                .and_then(Value::as_array)
                .with_context(|| format!("item recipients are not an array: {id}"))?
                .clone();
            let mut retained_recipient_uids = Vec::new();
            let mut fingerprints = Vec::new();
            for stored_uid in stored_recipient_uids {
                let uid = stored_uid
                    .as_str()
                    .with_context(|| format!("item recipient UID is not a string: {id}"))?;
                let fingerprint = recipient_fingerprints
                    .get(uid)
                    .with_context(|| format!("item references recipient without a key: {id}"))?;
                let is_automatic_owner = uid == old_owner_uid
                    || uid == new_owner_uid
                    || fingerprint.eq_ignore_ascii_case(&old_owner_fingerprint)
                    || fingerprint.eq_ignore_ascii_case(new_owner_fingerprint);
                if !is_automatic_owner
                    && checked_shared_fingerprints.insert(fingerprint.to_ascii_uppercase())
                    && !crypto::public_key_exists(fingerprint)?
                {
                    bail!("item shared-recipient public key is missing: {id}");
                }
                if !is_automatic_owner {
                    retained_recipient_uids.push(Value::String(uid.to_string()));
                    push_unique_fingerprint(&mut fingerprints, fingerprint);
                }
            }
            push_unique_fingerprint(&mut fingerprints, &recovery_fingerprint);
            push_unique_fingerprint(&mut fingerprints, new_owner_fingerprint);

            let current = entry
                .get("current")
                .and_then(Value::as_str)
                .with_context(|| format!("item has no current ciphertext: {id}"))?;
            let rewrapped_current = rewrap_ciphertext(current, &fingerprints)
                .with_context(|| format!("rewrap current item version: {id}"))?;
            entry.insert("current".to_string(), Value::String(rewrapped_current));
            version_count =
                version_count.saturating_add(std::iter::once(()).count());

            let history = entry
                .get_mut("history")
                .and_then(Value::as_array_mut)
                .with_context(|| format!("item history is not an array: {id}"))?;
            for (index, historical) in history.iter_mut().enumerate() {
                let historical_entry = historical.as_object_mut().with_context(|| {
                    format!("item history entry is not an object: {id} version {index}")
                })?;
                let ciphertext = historical_entry
                    .get("cipher")
                    .and_then(Value::as_str)
                    .with_context(|| {
                        format!("item history entry has no ciphertext: {id} version {index}")
                    })?;
                let rewrapped = rewrap_ciphertext(ciphertext, &fingerprints).with_context(|| {
                    format!("rewrap historical item version: {id} version {index}")
                })?;
                historical_entry.insert("cipher".to_string(), Value::String(rewrapped));
                version_count =
                    version_count.saturating_add(std::iter::once(()).count());
            }
            entry.insert(
                "recipients".to_string(),
                Value::Array(retained_recipient_uids),
            );
            item_count = item_count.saturating_add(std::iter::once(()).count());
        }

        let recipients = obj_mut(&mut staged, "recipients");
        recipients.remove(&old_owner_uid);
        recipients.insert(
            new_owner_uid.to_string(),
            json!({
                "fingerprint": new_owner_fingerprint,
                "role": "owner",
                "added_at": now(),
            }),
        );
        staged
            .as_object_mut()
            .context("vault document is not an object")?
            .insert("owner".to_string(), json!(new_owner_uid));

        let original = std::mem::replace(&mut self.doc, staged);
        if let Err(error) = self.save() {
            self.doc = original;
            return Err(error);
        }
        Ok(OwnerRotationReport {
            items: item_count,
            versions: version_count,
            old_fingerprint: old_owner_fingerprint,
            new_fingerprint: new_owner_fingerprint.to_string(),
        })
    }

    // Trash (soft delete): recoverable. Purge removes permanently.
    pub fn delete_item(&mut self, id: &str) -> Result<()> {
        let stamp = now();
        let items = obj_mut(&mut self.doc, "items");
        let item = items
            .get_mut(id)
            .with_context(|| format!("no item: {id}"))?;
        let entry = item.as_object_mut().context("item is object")?;
        entry.insert("deleted".to_string(), Value::Bool(true));
        entry.insert("deleted_at".to_string(), json!(stamp));
        self.save()
    }

    pub fn restore_item(&mut self, id: &str) -> Result<()> {
        let items = obj_mut(&mut self.doc, "items");
        let item = items
            .get_mut(id)
            .with_context(|| format!("no item: {id}"))?;
        let entry = item.as_object_mut().context("item is object")?;
        entry.insert("deleted".to_string(), Value::Bool(false));
        entry.insert("deleted_at".to_string(), Value::Null);
        self.save()
    }

    pub fn purge_item(&mut self, id: &str) -> Result<()> {
        obj_mut(&mut self.doc, "items")
            .remove(id)
            .with_context(|| format!("no item: {id}"))?;
        self.save()
    }

    // Restore a prior version by its timestamp: the chosen history ciphertext
    // becomes current, and the replaced current is appended to history.
    pub fn restore_version(&mut self, id: &str, at: &str) -> Result<()> {
        let stamp = now();
        let items = obj_mut(&mut self.doc, "items");
        let item = items
            .get_mut(id)
            .with_context(|| format!("no item: {id}"))?;
        let history = item
            .get("history")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let chosen = history
            .iter()
            .find(|e| e.get("at").and_then(Value::as_str) == Some(at))
            .with_context(|| format!("no version at {at} for {id}"))?
            .get("cipher")
            .cloned()
            .context("history entry missing cipher")?;
        let entry = item.as_object_mut().context("item is object")?;
        if let (Some(cur_at), Some(cur)) = (
            entry.get("updated_at").cloned(),
            entry.get("current").cloned(),
        ) {
            let mut h = history;
            h.push(json!({"at": cur_at, "cipher": cur}));
            entry.insert("history".to_string(), Value::Array(h));
        }
        entry.insert("current".to_string(), chosen);
        entry.insert("updated_at".to_string(), json!(stamp));
        self.save()
    }
}
