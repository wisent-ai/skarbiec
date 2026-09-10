// Where issued acquisitions and spent proofs are recorded: an owner-only
// file, one writer at a time, and the expiry that empties it again.

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::vault_path;

pub(super) struct StateLock(File);

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub(super) fn private_file_mode() -> Result<u32> {
    u32::from_str_radix("600", "8".parse()?).context("private file mode")
}

pub(super) fn unsafe_mode_bits() -> Result<u32> {
    u32::from_str_radix("077", "8".parse()?).context("unsafe mode bits")
}

pub(super) fn effective_uid() -> Result<u32> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("read effective uid")?;
    if !output.status.success() {
        bail!("could not determine effective uid");
    }
    String::from_utf8(output.stdout)?
        .trim()
        .parse()
        .context("parse effective uid")
}

pub(super) fn state_path() -> PathBuf {
    if let Ok(path) = std::env::var("SKARBIEC_ACQUISITION_FILE") {
        return PathBuf::from(path);
    }
    let vault = vault_path();
    let name = vault
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.acquisitions.json"))
        .unwrap_or_else(|| "skarbiec.vault.acquisitions.json".to_string());
    vault.with_file_name(name)
}

pub(super) fn lock_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.advisory.lock"))
        .unwrap_or_else(|| "skarbiec.vault.acquisitions.advisory.lock".to_string());
    path.with_file_name(name)
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
    let attempts: usize = "500".parse()?;
    let pause = Duration::from_millis("10".parse()?);
    for _ in std::iter::repeat_n((), attempts) {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(StateLock(file)),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(pause),
            Err(error) => return Err(error).context("lock acquisition state"),
        }
    }
    bail!("acquisition state is locked")
}

pub(super) fn validate_owned_regular(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.uid() != effective_uid()? {
        bail!("acquisition state must be an owner-controlled regular file");
    }
    if metadata.mode() & unsafe_mode_bits()? != u32::MIN {
        bail!("acquisition state permissions must not grant group or other access");
    }
    Ok(())
}

pub(super) fn load_state(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(json!({"version": "v1", "tokens": {}, "proofs": {}}));
    }
    validate_owned_regular(path)?;
    let mut state: Value =
        serde_json::from_str(&fs::read_to_string(path)?).context("parse acquisition state")?;
    if state.get("version").and_then(Value::as_str) != Some("v1")
        || !state.get("tokens").is_some_and(Value::is_object)
    {
        bail!("invalid acquisition state document");
    }
    if state.get("proofs").is_none() {
        state["proofs"] = json!({});
    }
    if !state.get("proofs").is_some_and(Value::is_object) {
        bail!("invalid acquisition proof state");
    }
    Ok(state)
}

pub(super) fn save_state(path: &Path, state: &Value) -> Result<()> {
    let parent = path.parent().context("acquisition state has no parent")?;
    fs::create_dir_all(parent)?;
    let suffix = format!("{}.{}", std::process::id(), now_epoch()?);
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
        let _ = File::open(parent).and_then(|directory| directory.sync_all());
        validate_owned_regular(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub(super) fn now_epoch() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub(super) fn ttl_seconds() -> Result<u64> {
    let ttl: u64 = std::env::var("SKARBIEC_ACQUISITION_TTL_SECONDS")
        .unwrap_or_else(|_| "30".to_string())
        .parse()
        .context("SKARBIEC_ACQUISITION_TTL_SECONDS must be an integer")?;
    let maximum: u64 = "300".parse()?;
    if ttl == u64::MIN || ttl > maximum {
        bail!("SKARBIEC_ACQUISITION_TTL_SECONDS must be between one and 300")
    }
    Ok(ttl)
}
