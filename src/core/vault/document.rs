// Opening, creating and writing the vault file itself: the parts that touch
// the document on disk rather than the items inside it.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

use super::{acquire_write_lock, atomic_write, document_generation, now, Vault};

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
}
