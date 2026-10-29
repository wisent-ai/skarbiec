// Opening, creating and writing the vault file itself: the parts that touch
// the document on disk rather than the items inside it.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use super::{acquire_write_lock, atomic_write, document_generation, now, Vault};

/// Another writer saved the vault after this copy was opened. A caller that
/// can re-open and re-apply its change asks for this type with
/// `downcast_ref`; the sentence is for the person reading the refusal.
#[derive(Debug)]
pub(crate) struct VaultChangedConcurrently {
    loaded: Option<NonZeroU64>,
    persisted: Option<NonZeroU64>,
}

/// A generation as a sentence reads it: the count of saves, or that the
/// document records none.
fn shown(generation: Option<NonZeroU64>) -> String {
    match generation {
        Some(generation) => generation.to_string(),
        None => "none".to_string(),
    }
}

impl std::fmt::Display for VaultChangedConcurrently {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "vault changed concurrently: loaded generation {}, persisted generation {}; reopen and retry",
            shown(self.loaded),
            shown(self.persisted)
        )
    }
}

impl std::error::Error for VaultChangedConcurrently {}

impl Vault {
    /// Whether a vault may be created at `path`: not a copy Stado's route says
    /// this machine must not hold, and no vault there yet. `init` asks before
    /// it makes any key, so a refused `init` leaves the keyring as it found it.
    pub fn creatable(path: &Path) -> Result<()> {
        if let Some(refusal) = crate::core::unchosen_copy_refusal(path) {
            bail!(refusal);
        }
        if crate::core::is_present(path, "vault")? {
            bail!("vault already exists at {}", path.display());
        }
        Ok(())
    }

    pub fn create(
        path: PathBuf,
        owner_uid: &str,
        owner_fpr: &str,
        recovery_fpr: &str,
    ) -> Result<Self> {
        Self::creatable(&path)?;
        // No generation yet: the first save below writes the first one.
        let doc = json!({
            "version": "v1",
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
            base_generation: None,
            owner: owner_uid.to_string(),
            recovery: recovery_fpr.to_string(),
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn open(path: PathBuf) -> Result<Self> {
        if let Some(refusal) = crate::core::unchosen_copy_refusal(&path) {
            bail!(refusal);
        }
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => match newest_kept_copy(&path)? {
                Some(copy) => bail!(
                    "vault not initialized at {path}: the file is gone, and {copy} is the newest copy \
                     kept beside it that reads as a vault; `skarbiec backup restore {copy}` says what \
                     it holds and with --yes puts it back (init would start an empty vault)",
                    path = path.display(),
                    copy = copy.display()
                ),
                None => bail!("vault not initialized at {} (run: init)", path.display()),
            },
            Err(error) => {
                return Err(error).with_context(|| format!("read vault file {}", path.display()));
            }
        };
        let doc: Value = serde_json::from_str(&text).with_context(|| {
            format!(
                "parse vault file {}: it is not the JSON document skarbiec writes",
                path.display()
            )
        })?;
        let base_generation =
            document_generation(&doc).with_context(|| format!("vault file {}", path.display()))?;
        // Who writes as the owner and which key recovers the vault are read
        // once, here: a document naming neither is refused, never read as an
        // owner called "" that items would then be written and controlled by.
        let owner = match doc.get("owner") {
            Some(Value::String(owner)) if !owner.is_empty() => owner.clone(),
            recorded => bail!(
                "vault file {} records its owner as {recorded:?}, not a user id, so who writes as the owner is unknown",
                path.display()
            ),
        };
        let recovery = match doc.get("recovery") {
            Some(Value::String(recovery)) => recovery.clone(),
            recorded => bail!(
                "vault file {} records its recovery key as {recorded:?}, not a fingerprint, so whether it can be recovered is unknown",
                path.display()
            ),
        };
        // init writes both sections, so a document without either as an
        // object is damaged. It is refused here once, so every reader of
        // items or recipients meets a whole section instead of reading the
        // damage as an empty vault.
        for (name, shape) in [("items", "id -> item"), ("recipients", "uid -> recipient")] {
            if !doc.get(name).is_some_and(Value::is_object) {
                bail!(
                    "vault file {} holds its {name} section as {:?}, not an object of {shape}, so the vault is damaged; `skarbiec backup restore <copy>` says what a kept copy holds and puts it back",
                    path.display(),
                    doc.get(name)
                );
            }
        }
        Ok(Self {
            path,
            doc,
            base_generation,
            owner,
            recovery,
        })
    }

    pub fn save(&mut self) -> Result<()> {
        if let Some(refusal) = crate::core::unchosen_copy_refusal(&self.path) {
            bail!(refusal);
        }
        let _write_lock = acquire_write_lock(&self.path)?;
        if let Some(text) = crate::core::read_present(&self.path, "persisted vault")? {
            let persisted: Value =
                serde_json::from_str(&text).context("parse persisted vault under write lock")?;
            let persisted_generation =
                document_generation(&persisted).context("the persisted vault under write lock")?;
            if persisted_generation != self.base_generation {
                return Err(VaultChangedConcurrently {
                    loaded: self.base_generation,
                    persisted: persisted_generation,
                }
                .into());
            }
        } else if self.base_generation.is_some() {
            bail!("vault disappeared before save; refusing to recreate it from stale state");
        }
        let next_generation = match self.base_generation {
            None => NonZeroU64::MIN,
            Some(generation) => generation
                .checked_add(NonZeroU64::MIN.get())
                .context("vault generation overflow")?,
        };
        let document = self
            .doc
            .as_object_mut()
            .context("vault document is not an object")?;
        let loaded = document.insert("generation".to_string(), json!(next_generation.get()));
        let mut encoded = serde_json::to_vec_pretty(&self.doc)?;
        encoded.push(b'\n');
        if let Err(error) = atomic_write(&self.path, &encoded) {
            // The copy in memory goes back to the generation it was opened at.
            let document = self
                .doc
                .as_object_mut()
                .context("vault document is not an object")?;
            match loaded {
                Some(loaded) => document.insert("generation".to_string(), loaded),
                None => document.remove("generation"),
            };
            return Err(error).context("atomically persist vault");
        }
        self.base_generation = Some(next_generation);
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

    /// The owner's user id, as the document named it when it was opened or
    /// as `rotate_owner` last set it.
    pub fn owner_uid(&self) -> &str {
        &self.owner
    }

    /// The recovery key's fingerprint; empty for a vault created without one.
    pub fn recovery_fpr(&self) -> &str {
        &self.recovery
    }
}

/// The newest copy of the vault file kept beside it (`<file>.pre-pull-…`,
/// `<file>.pre-restore.…` or any other `<file>.<suffix>`) that reads as a
/// vault, newest by modification time. A sibling that does not read as a
/// vault (the capability state, a lock) is not a copy and is passed over, so
/// a vault that vanished is answered with the copy that brings it back.
fn newest_kept_copy(path: &Path) -> Result<Option<PathBuf>> {
    let (Some(directory), Some(name)) = (
        path.parent(),
        path.file_name().and_then(|name| name.to_str()),
    ) else {
        return Ok(None);
    };
    let prefix = format!("{name}.");
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("list {}", directory.display())),
    };
    let mut copies = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("list {}", directory.display()))?;
        let kept = entry
            .file_name()
            .to_str()
            .is_some_and(|file| file.starts_with(&prefix));
        if !kept {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .with_context(|| format!("examine {}", entry.path().display()))?;
        copies.push((modified, entry.path()));
    }
    copies.sort();
    for (_modified, copy) in copies.into_iter().rev() {
        match Vault::open(copy.clone()) {
            Ok(_vault) => return Ok(Some(copy)),
            Err(_not_a_vault) => continue,
        }
    }
    Ok(None)
}
