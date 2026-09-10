// Storing an item: the callers' entry points, the atomic multi-item write, and
// the process attribution recorded beside each write.

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::core::vault::{obj_mut, ItemWrite, ManagedWrite, Vault, WritePolicy};

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
    pub(in crate::core::vault) fn parent_process() -> (String, String) {
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

    pub(crate) fn set_items_atomic(&mut self, writes: &[ItemWrite<'_>]) -> Result<()> {
        if writes.is_empty() {
            return Ok(());
        }
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
        let items = obj_mut(&mut self.doc, "items");
        for (id, entry, audit) in prepared {
            let old = items.insert(id.clone(), entry);
            previous.push((id, old));
            audits.push(audit);
        }
        if let Err(error) = self.save() {
            let items = obj_mut(&mut self.doc, "items");
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
            crate::runtime::audit::append_sync("item-write", &audit).ok();
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
        let (entry, audit) =
            self.prepare_item_with_writer(id, item_kind, payload, recipient_uids, tags, policy)?;
        let previous = obj_mut(&mut self.doc, "items").insert(id.to_string(), entry);
        if let Err(error) = self.save() {
            let items = obj_mut(&mut self.doc, "items");
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
        crate::runtime::audit::append_sync("item-write", &audit).ok();
        Ok(())
    }

}
