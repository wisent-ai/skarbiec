// Where issued acquisitions and spent proofs are recorded: an owner-only
// file, one writer at a time, and the expiry that empties it again.

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde_json::{json, Value};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::num::NonZeroU32;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use stado_wait as wait;

use crate::core::vault::private_file_mode;
use crate::core::{effective_uid, vault_path};

/// The held lock on the acquisition state; closing the file releases it.
pub(super) struct StateLock {
    _file: File,
}

/// Group and other permission bits, as the C library names them; an owner-only
/// file has none of them.
fn unsafe_mode_bits() -> u32 {
    u32::from(libc::S_IRWXG | libc::S_IRWXO)
}

/// `path` with `suffix` appended to its last component.
fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path);
    name.push(suffix);
    PathBuf::from(name)
}

/// The acquisition state beside the vault, unless
/// `SKARBIEC_ACQUISITION_FILE` names another.
pub(super) fn state_path() -> PathBuf {
    if let Some(path) = crate::core::env::path("SKARBIEC_ACQUISITION_FILE") {
        return path;
    }
    suffixed(&vault_path(), ".acquisitions.json")
}

pub(super) fn lock_path(path: &Path) -> PathBuf {
    suffixed(path, ".advisory.lock")
}

pub(super) fn acquire_lock(path: &Path) -> Result<StateLock> {
    let lock = lock_path(path);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(private_file_mode()?)
        .open(&lock)
        .with_context(|| format!("open acquisition state lock {}", lock.display()))?;
    validate_owned_regular(&lock)?;
    // The kernel queues this process until the holder releases the lock or
    // exits; a failure to lock is the error itself.
    let what = "the acquisition state lock";
    wait::blocking(wait::Kind::Lock, what, lock.display(), || {
        file.lock_exclusive()
    })
    .context("lock acquisition state")?;
    Ok(StateLock { _file: file })
}

pub(super) fn validate_owned_regular(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect acquisition state {}", path.display()))?;
    validate_owned_metadata(path, &metadata)
}

fn validate_owned_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if !metadata.file_type().is_file() || metadata.uid() != effective_uid() {
        bail!(
            "acquisition state {} must be an owner-controlled regular file",
            path.display()
        );
    }
    if NonZeroU32::new(metadata.mode() & unsafe_mode_bits()).is_some() {
        bail!(
            "acquisition state {} permissions must not grant group or other access",
            path.display()
        );
    }
    Ok(())
}

/// The document a state file starts as; every object in it is a section an
/// older file may lack.
fn fresh_state() -> Value {
    json!({"version": "v1", "tokens": {}, "proofs": {}, "workloads": {}})
}

pub(super) fn load_state(path: &Path) -> Result<Value> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(fresh_state()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect acquisition state {}", path.display()));
        }
    };
    validate_owned_metadata(path, &metadata)?;
    let document = fs::read_to_string(path)
        .with_context(|| format!("read acquisition state {}", path.display()))?;
    let mut state: Value = serde_json::from_str(&document)
        .with_context(|| format!("parse acquisition state {}", path.display()))?;
    if state.get("version").and_then(Value::as_str) != Some("v1")
        || !state.get("tokens").is_some_and(Value::is_object)
    {
        bail!("invalid acquisition state document");
    }
    let fresh = fresh_state();
    for (section, empty) in fresh.as_object().into_iter().flatten() {
        if !empty.is_object() {
            continue;
        }
        if state.get(section).is_none() {
            state[section] = empty.clone();
        }
        if !state.get(section).is_some_and(Value::is_object) {
            bail!("invalid acquisition {section} state");
        }
    }
    Ok(state)
}

pub(super) fn save_state(path: &Path, state: &Value) -> Result<()> {
    let parent = path.parent().context("acquisition state has no parent")?;
    fs::create_dir_all(parent)?;
    let suffix = format!(
        "{}.{}",
        std::process::id(),
        crate::core::clock::epoch_seconds()?
    );
    let temp = path.with_extension(format!("tmp.{suffix}"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(private_file_mode()?)
        .open(&temp)
        .context("create acquisition state temporary file")?;
    let result = (|| -> Result<()> {
        file.write_all(serde_json::to_string_pretty(state)?.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(private_file_mode()?))?;
        fs::rename(&temp, path)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("flush acquisition state directory {}", parent.display()))?;
        validate_owned_regular(path)
    })();
    if result.is_err() {
        crate::core::staging::remove_said(
            &temp,
            "a failed acquisition state write left its temporary file",
        );
    }
    result
}
