// Storing an item: the callers' entry points, the atomic multi-item write, and
// the process attribution recorded beside each write.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::core::vault::items::duplicates;
use crate::core::vault::{mint_item_uid, obj_mut, ItemWrite, ManagedWrite, Vault, WritePolicy};

impl Vault {
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
                item_uid: None,
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
                item_uid: None,
            },
        )
    }

    /// Write an item that already has an identity in another vault.
    ///
    /// The cross-vault `migrate` copies an item between vaults, and the item on
    /// the far side is the same item: carrying its uid across is what lets a
    /// route table or a consumer config that referred to it still be traced.
    /// The supplied uid is only ever adopted when the target has no item under
    /// this id; if one is already there, that item's own identity wins, because
    /// overwriting an item's contents does not make it a different item.
    pub fn set_migrated_item(
        &mut self,
        id: &str,
        item_kind: &str,
        payload: &Value,
        recipient_uids: &[String],
        tags: &[String],
        item_uid: Option<&str>,
    ) -> Result<()> {
        self.set_item_with_writer(
            id,
            item_kind,
            payload,
            recipient_uids,
            tags,
            WritePolicy {
                writer: None,
                managed: None,
                item_uid,
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
    /// The pid is the kernel's answer for this process. The parent's program is
    /// read with `ps`, run through the announced wait, and only the program is
    /// kept, never the rest of the argument vector: this line lands in a journal
    /// an operator reads, and a parent that was handed a secret on its command
    /// line must not have it copied here. A program that cannot be read does not
    /// fail the credential write; the journal carries `not read: <cause>` in its
    /// place, never an empty name that reads as a program nobody ran.
    pub(in crate::core::vault) fn parent_process() -> (String, String) {
        let pid = std::os::unix::process::parent_id().to_string();
        let program = stado_wait::output(
            std::process::Command::new("/bin/ps").args(["-o", "command=", "-p", &pid]),
        )
        .map_err(|error| format!("/bin/ps could not be run for pid {pid}: {error:#}"))
        .and_then(|output| {
            if !output.status.success() {
                return Err(format!(
                    "/bin/ps -p {pid} exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            let command = String::from_utf8(output.stdout)
                .map_err(|error| format!("/bin/ps -p {pid} printed no text: {error}"))?;
            command
                .split_whitespace()
                .next()
                .map(str::to_string)
                .ok_or_else(|| format!("/bin/ps -p {pid} printed no command"))
        });
        match program {
            Ok(program) => (pid, program),
            Err(cause) => (pid, format!("not read: {cause}")),
        }
    }

    /// The salt this vault's payload fingerprints are taken under, minted on
    /// first need and never replaced.
    ///
    /// Lazily rather than at `init`, because every vault that already exists
    /// was created before fingerprints did: a vault with no salt is the
    /// normal state of an old vault, and the first write is the moment the
    /// vault can carry one. Replacing it later would silently unlink every
    /// fingerprint already stored, so an existing salt always wins.
    pub(in crate::core::vault) fn ensure_fingerprint_salt(&mut self) -> Result<()> {
        if self
            .doc
            .get(duplicates::SALT_KEY)
            .and_then(Value::as_str)
            .is_some_and(|salt| !salt.is_empty())
        {
            return Ok(());
        }
        let salt = mint_item_uid()?;
        self.doc
            .as_object_mut()
            .context("vault document is not an object")?
            .insert(duplicates::SALT_KEY.to_string(), json!(salt));
        Ok(())
    }

    pub(crate) fn set_items_atomic(&mut self, writes: &[ItemWrite<'_>]) -> Result<()> {
        if writes.is_empty() {
            return Ok(());
        }
        self.ensure_fingerprint_salt()?;
        let mut ids = std::collections::HashSet::with_capacity(writes.len());
        let mut prepared = Vec::with_capacity(writes.len());
        for write in writes {
            if !ids.insert(write.id) {
                bail!("duplicate item in import: {}", write.id);
            }
            let (mut entry, audit) = self.prepare_item_with_writer(
                write.id,
                write.kind,
                write.payload,
                write.recipients,
                write.tags,
                WritePolicy::default(),
            )?;
            if let Some(source) = write.import_source {
                entry["import_source"] = json!(source);
            }
            prepared.push((write.id.to_string(), entry, audit));
        }
        let mut previous = Vec::with_capacity(prepared.len());
        let mut audits = Vec::with_capacity(prepared.len());
        let items = obj_mut(&mut self.doc, "items")?;
        for (id, entry, audit) in prepared {
            let old = items.insert(id.clone(), entry);
            previous.push((id, old));
            audits.push(audit);
        }
        if let Err(error) = self.save() {
            // The save failed; its error is the answer, and a rollback that
            // cannot reach the section is said beside it.
            let items = match obj_mut(&mut self.doc, "items") {
                Ok(items) => items,
                Err(lost) => return Err(error.context(format!("the in-memory rollback failed too: {lost:#}"))),
            };
            for (id, old) in previous {
                match old {
                    Some(entry) => {
                        items.insert(id, entry);
                    }
                    None => {
                        items.remove(&id);
                    }
                }
            }
            return Err(error);
        }
        for audit in audits {
            audited(&audit);
        }
        Ok(())
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
        self.ensure_fingerprint_salt()?;
        let (entry, audit) =
            self.prepare_item_with_writer(id, item_kind, payload, recipient_uids, tags, policy)?;
        let previous = obj_mut(&mut self.doc, "items")?.insert(id.to_string(), entry);
        if let Err(error) = self.save() {
            let items = match obj_mut(&mut self.doc, "items") {
                Ok(items) => items,
                Err(lost) => return Err(error.context(format!("the in-memory rollback failed too: {lost:#}"))),
            };
            match previous {
                Some(entry) => {
                    items.insert(id.to_string(), entry);
                }
                None => {
                    items.remove(id);
                }
            }
            return Err(error);
        }
        audited(&audit);
        Ok(())
    }
}

/// Records an item write that has already been saved. The write stands either
/// way, so an audit entry that cannot be appended is said with its cause
/// rather than failing a write the vault already holds.
fn audited(audit: &Value) {
    if let Err(error) = crate::runtime::audit::append_sync("item-write", audit) {
        eprintln!(
            "skarbiec: an item write was saved but its audit entry was not recorded: {error:#}"
        );
    }
}
