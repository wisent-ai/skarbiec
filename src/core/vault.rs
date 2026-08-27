// Encrypted per-recipient vault document for skarbiec. Every item is gpg-armored
// ciphertext encrypted to the public keys of its recipients (always the owner
// and the recovery key, plus anyone it is shared with). The on-disk file is an
// index of that ciphertext plus non-secret metadata — safe at rest.
//
// All numbers enter at runtime (argv / stored JSON written by the compiled
// binary), never as literals in this source.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::{crypto, schema};

pub struct Vault {
    pub path: PathBuf,
    doc: Value,
    base_generation: u64,
}
#[derive(Clone, Copy)]
pub struct ManagedWrite<'a> {
    pub controller: &'a str,
    pub writer: &'a str,
    pub operation_id: Option<&'a str>,
}

#[derive(Default)]
struct WritePolicy<'a> {
    writer: Option<&'a str>,
    managed: Option<ManagedWrite<'a>>,
}

struct VaultWriteLock(PathBuf);

impl Drop for VaultWriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn acquire_write_lock(vault_path: &Path) -> Result<VaultWriteLock> {
    let lock_path = vault_path.with_extension("write.lock");
    let parent = lock_path.parent().context("vault path has no parent")?;
    if !parent.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(u32::from_str_radix("700", "8".parse()?)?)
            .create(parent)
            .with_context(|| format!("create vault directory {}", parent.display()))?;
    }
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(private_file_mode()?)
        .open(&lock_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!(
                "another process owns the vault write lock {}; verify it is no longer running before removing a stale lock",
                lock_path.display()
            )
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("create vault write lock {}", lock_path.display()))
        }
    };
    let guard = VaultWriteLock(lock_path);
    writeln!(file, "{}", std::process::id())?;
    file.sync_all()?;
    Ok(guard)
}

fn private_file_mode() -> Result<u32> {
    u32::from_str_radix("600", "8".parse()?).context("private vault file mode")
}

/// The only item envelope revision this build reads. It was written inline at
/// each comparison, so a reader could not tell which number was load-bearing.
pub fn current_envelope() -> u64 {
    "2".parse().expect("envelope revision is a number")
}

fn document_generation(doc: &Value) -> u64 {
    doc.get("generation")
        .and_then(Value::as_u64)
        .unwrap_or_default()
}

fn atomic_write(path: &Path, body: &[u8]) -> Result<()> {
    let parent = path.parent().context("vault path has no parent")?;
    let temp = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(private_file_mode()?)
        .open(&temp)
        .with_context(|| format!("create vault temporary file {}", temp.display()))?;
    let result = (|| -> Result<()> {
        file.write_all(body)?;
        file.sync_all()?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(private_file_mode()?))?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
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
        if path.exists() {
            bail!("vault already exists at {}", path.display());
        }
        let doc = json!({
            "version": "v1",
            "generation": u64::MIN,
            "owner": owner_uid,
            "recovery": recovery_fpr,
            "recipients": { owner_uid: {"fingerprint": owner_fpr, "role": "owner", "added_at": now()} },
            "items": {},
            "tokens": {},
            "policy": {},
        });
        let mut vault = Self {
            path,
            doc,
            base_generation: u64::MIN,
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn open(path: PathBuf) -> Result<Self> {
        if !path.exists() {
            bail!("vault not initialized at {} (run: init)", path.display());
        }
        let doc: Value =
            serde_json::from_str(&fs::read_to_string(&path)?).context("parse vault file")?;
        let base_generation = document_generation(&doc);
        Ok(Self {
            path,
            doc,
            base_generation,
        })
    }

    pub fn save(&mut self) -> Result<()> {
        let _write_lock = acquire_write_lock(&self.path)?;
        if self.path.exists() {
            let persisted: Value = serde_json::from_str(&fs::read_to_string(&self.path)?)
                .context("parse persisted vault under write lock")?;
            let persisted_generation = document_generation(&persisted);
            if persisted_generation != self.base_generation {
                bail!(
                    "vault changed concurrently: loaded generation {}, persisted generation {}; reopen and retry",
                    self.base_generation,
                    persisted_generation
                );
            }
        } else if self.base_generation != u64::MIN {
            bail!("vault disappeared before save; refusing to recreate it from stale state");
        }
        let next_generation = self
            .base_generation
            .checked_add(std::iter::once(()).count() as u64)
            .context("vault generation overflow")?;
        self.doc
            .as_object_mut()
            .context("vault document is not an object")?
            .insert("generation".to_string(), json!(next_generation));
        let mut encoded = serde_json::to_vec_pretty(&self.doc)?;
        encoded.push(b'\n');
        if let Err(error) = atomic_write(&self.path, &encoded) {
            self.doc
                .as_object_mut()
                .context("vault document is not an object")?
                .insert("generation".to_string(), json!(self.base_generation));
            return Err(error).context("atomically persist vault");
        }
        self.base_generation = next_generation;
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

    // Store a validated canonical item. Administrative callers may replace the
    // payload and metadata; managed workloads use `set_managed_item`, which
    // preserves protected envelope metadata.
    pub fn set_item(
        &mut self,
        id: &str,
        item_kind: &str,
        payload: &Value,
        recipient_uids: &[String],
        tags: &[String],
    ) -> Result<()> {
        self.set_item_with_writer(
            id,
            item_kind,
            payload,
            recipient_uids,
            tags,
            WritePolicy::default(),
        )
    }

    pub fn set_item_written_by(
        &mut self,
        id: &str,
        item_kind: &str,
        payload: &Value,
        recipient_uids: &[String],
        tags: &[String],
        writer: &str,
    ) -> Result<()> {
        self.set_item_with_writer(
            id,
            item_kind,
            payload,
            recipient_uids,
            tags,
            WritePolicy {
                writer: Some(writer),
                managed: None,
            },
        )
    }

    pub fn set_managed_item(
        &mut self,
        id: &str,
        item_kind: &str,
        payload: &Value,
        recipient_uids: &[String],
        tags: &[String],
        write: ManagedWrite<'_>,
    ) -> Result<()> {
        self.set_item_with_writer(
            id,
            item_kind,
            payload,
            recipient_uids,
            tags,
            WritePolicy {
                writer: Some(write.writer),
                managed: Some(write),
            },
        )
    }

    /// The parent process behind this write: its pid and the program it runs.
    ///
    /// A vault write records the owner key that signed it, which on one host is the
    /// same string for every write and therefore names nobody. The parent command is
    /// what tells an operator whether a rotation came from the gateway, a helper or a
    /// scheduled job, and it is the question this journal was added to answer: a
    /// bare parent pid is a number that has already exited by the time anyone reads
    /// the line.
    ///
    /// Two `ps` reads, because one cannot answer it. `ps -p <self>` prints this
    /// process's own ppid and its own command, so the command in that row names the
    /// writer again rather than whoever invoked it; the parent's program comes from
    /// a second read of the ppid it just produced.
    ///
    /// Only the program is kept, never the rest of the argument vector: this line
    /// lands in a journal an operator reads, and a parent that was handed a secret
    /// on its command line must not have it copied here. Best effort by design: an
    /// unavailable parent yields empty strings rather than failing a credential
    /// write.
    fn parent_process() -> (String, String) {
        let read = |format: &str, pid: &str| -> String {
            std::process::Command::new("/bin/ps")
                .args(["-o", format, "-p", pid])
                .output()
                .ok()
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .unwrap_or_default()
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string()
        };
        let parent_pid = read("ppid=", &std::process::id().to_string());
        if parent_pid.is_empty() {
            return (parent_pid, String::new());
        }
        let program = read("command=", &parent_pid);
        (parent_pid, program)
    }

    fn set_item_with_writer(
        &mut self,
        id: &str,
        item_kind: &str,
        payload: &Value,
        recipient_uids: &[String],
        tags: &[String],
        policy: WritePolicy<'_>,
    ) -> Result<()> {
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
        let entry = json!({
            "format": current_envelope(),
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
        obj_mut(&mut self.doc, "items").insert(id.to_string(), entry);
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
        crate::runtime::audit::append_sync(
            "item-write",
            &json!({
                "item": id,
                "kind": item_kind,
                "revision": revision,
                "tags": stored_tags,
                "tags_requested": tags.len(),
                "pid": std::process::id(),
                "process": std::env::args().next().unwrap_or_default(),
                "parent_pid": parent_pid,
                "parent_process": parent_process,
            }),
        )
        .ok();
        self.save()
    }

    /// Replace one item's tags without touching its payload.
    ///
    /// Tags sit beside the envelope, not inside it: they are how consumers
    /// enumerate what an item is, and nothing about the ciphertext, the
    /// recipient list or the revision depends on them. Setting them through
    /// `set_item_with_writer` would re-encrypt the payload to whatever
    /// recipients the entry carries now, which for an item written with an
    /// empty recipient list narrows access to a credential that is in use, and
    /// requires decrypting it first. This writes the metadata alone.
    pub fn set_item_tags(&mut self, id: &str, tags: &[String]) -> Result<()> {
        let mut entry = self
            .doc
            .get("items")
            .and_then(Value::as_object)
            .and_then(|items| items.get(id))
            .cloned()
            .with_context(|| format!("no item: {id}"))?;
        if entry.get("format").and_then(Value::as_u64) != Some(current_envelope()) {
            bail!("{id} still uses the legacy envelope; run migrate-v2 before updating it");
        }
        entry["tags"] = tags.iter().cloned().map(Value::String).collect();
        entry["updated_at"] = json!(now());
        obj_mut(&mut self.doc, "items").insert(id.to_string(), entry);
        self.save()
    }

    pub fn stage_managed_field(
        &mut self,
        id: &str,
        field: &str,
        value: Value,
        expected_revision: u64,
        write: ManagedWrite<'_>,
    ) -> Result<u64> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        if item.get("format").and_then(Value::as_u64) != Some(current_envelope()) {
            bail!("item uses the legacy envelope: {id} (run migrate-v2)");
        }
        if item.get("state").and_then(Value::as_str) != Some("active") {
            bail!("{id} is not active");
        }
        if item.get("revision").and_then(Value::as_u64) != Some(expected_revision) {
            bail!("item revision changed; reopen and retry the operation");
        }
        let management = item
            .get("management")
            .and_then(Value::as_object)
            .context("managed item has no management envelope")?;
        if management.get("mode").and_then(Value::as_str) != Some("managed")
            || management.get("controller").and_then(Value::as_str) != Some(write.controller)
        {
            bail!("{id} is controlled by a different management authority");
        }
        if item
            .get("current")
            .and_then(|current| current.get("written_by"))
            .and_then(Value::as_str)
            != Some(write.writer)
        {
            bail!("{id} may only be staged by its exact active writer");
        }
        if let Some(pending) = item.get("pending") {
            if pending.get("operation_id").and_then(Value::as_str) == write.operation_id {
                return pending
                    .get("revision")
                    .and_then(Value::as_u64)
                    .context("pending revision has no revision number");
            }
            bail!("{id} already has a different staged revision");
        }
        let kind = item
            .get("kind")
            .and_then(Value::as_str)
            .context("canonical item has no kind")?
            .to_string();
        let recipients = self.item_recipient_uids(id);
        let mut payload = self.get_item(id)?;
        schema::fields(&payload)?;
        let same_as_current = schema::field(&payload, field).ok() == Some(&value);
        payload
            .get_mut("fields")
            .and_then(Value::as_object_mut)
            .context("canonical item has no mutable fields object")?
            .insert(field.to_string(), value);
        schema::validate_payload(&payload, &kind)?;
        let revision = expected_revision
            .checked_add(std::iter::once(()).count() as u64)
            .context("item revision overflow")?;
        let cipher = crypto::encrypt_to(
            &self.fprs_for(&recipients),
            &serde_json::to_string(&payload)?,
        )?;
        let stamp = now();
        obj_mut(&mut self.doc, "items")
            .get_mut(id)
            .and_then(Value::as_object_mut)
            .context("canonical item is not an object")?
            .insert(
                "pending".to_string(),
                json!({
                    "revision": revision,
                    "created_at": stamp,
                    "kind": kind,
                    "written_by": write.writer,
                    "operation_id": write.operation_id,
                    "field": field,
                    "same_as_current": same_as_current,
                    "ciphertext": cipher,
                }),
            );
        self.save()?;
        Ok(revision)
    }
    pub fn trash_managed_item(&mut self, id: &str, controller: &str, writer: &str) -> Result<()> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        let management = item
            .get("management")
            .and_then(Value::as_object)
            .context("managed item has no management envelope")?;
        if item.get("state").and_then(Value::as_str) != Some("active")
            || management.get("mode").and_then(Value::as_str) != Some("managed")
            || management.get("controller").and_then(Value::as_str) != Some(controller)
            || item
                .get("current")
                .and_then(|current| current.get("written_by"))
                .and_then(Value::as_str)
                != Some(writer)
        {
            bail!("{id} is not controlled by this exact management writer");
        }
        if item.get("pending").is_some() {
            bail!("{id} has a staged revision; resolve it before removal");
        }
        let entry = obj_mut(&mut self.doc, "items")
            .get_mut(id)
            .and_then(Value::as_object_mut)
            .context("canonical item is not an object")?;
        entry.insert("state".to_string(), json!("trashed"));
        entry.insert("deleted_at".to_string(), json!(now()));
        self.save()
    }

    pub fn activate_staged_revision(
        &mut self,
        id: &str,
        operation_id: &str,
        field: &str,
        writer: &str,
    ) -> Result<u64> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        let pending = item
            .get("pending")
            .cloned()
            .context("item has no staged revision")?;
        if pending.get("operation_id").and_then(Value::as_str) != Some(operation_id)
            || pending.get("field").and_then(Value::as_str) != Some(field)
            || pending.get("written_by").and_then(Value::as_str) != Some(writer)
        {
            bail!("staged revision does not belong to this operation and writer");
        }
        let revision = pending
            .get("revision")
            .and_then(Value::as_u64)
            .context("staged revision has no revision number")?;
        let mut history = item
            .get("history")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        history.push(
            item.get("current")
                .cloned()
                .context("canonical item has no current revision")?,
        );
        let stamp = now();
        let entry = obj_mut(&mut self.doc, "items")
            .get_mut(id)
            .and_then(Value::as_object_mut)
            .context("canonical item is not an object")?;
        entry.insert("current".to_string(), pending);
        entry.insert("history".to_string(), Value::Array(history));
        entry.insert("revision".to_string(), json!(revision));
        entry.insert("updated_at".to_string(), json!(stamp));
        entry.remove("pending");
        self.save()?;
        Ok(revision)
    }

    pub fn discard_staged_revision(
        &mut self,
        id: &str,
        operation_id: &str,
        field: &str,
        writer: &str,
    ) -> Result<()> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        let pending = item.get("pending").context("item has no staged revision")?;
        if pending.get("operation_id").and_then(Value::as_str) != Some(operation_id)
            || pending.get("field").and_then(Value::as_str) != Some(field)
            || pending.get("written_by").and_then(Value::as_str) != Some(writer)
        {
            bail!("staged revision does not belong to this operation and writer");
        }
        obj_mut(&mut self.doc, "items")
            .get_mut(id)
            .and_then(Value::as_object_mut)
            .context("canonical item is not an object")?
            .remove("pending");
        self.save()
    }

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
