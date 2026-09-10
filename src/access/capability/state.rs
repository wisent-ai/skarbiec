// Where a capability and its spent nonces are recorded, and the lock that
// keeps two redemptions from spending the same use.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::{STATE_LOCK_ATTEMPTS, STATE_LOCK_RETRY_MILLIS, STATE_LOCK_STALE_SECONDS};
use crate::core::vault_path;

pub(in crate::access::capability) struct StateLock {
    path: PathBuf,
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

pub(in crate::access::capability) fn acquire_state_lock() -> Result<StateLock> {
    let path = state_path().with_extension("json.lock");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    for _ in 0..STATE_LOCK_ATTEMPTS {
        match fs::create_dir(&path) {
            Ok(()) => return Ok(StateLock { path }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let stale = fs::metadata(&path)
                    .and_then(|metadata| metadata.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age.as_secs() > STATE_LOCK_STALE_SECONDS);
                if stale {
                    let _ = fs::remove_dir(&path);
                    continue;
                }
                std::thread::sleep(std::time::Duration::from_millis(STATE_LOCK_RETRY_MILLIS));
            }
            Err(error) => return Err(error).context("create capability state lock"),
        }
    }
    bail!("timed out acquiring capability state lock")
}

/// Where the capability records live: `SKARBIEC_CAPABILITY_FILE` when an
/// operator names one, and otherwise the vault's own path with
/// `.capabilities.json` beside it, so a second vault never shares the first
/// one's records.
pub(in crate::access::capability) fn state_path() -> PathBuf {
    if let Ok(path) = std::env::var("SKARBIEC_CAPABILITY_FILE") {
        return PathBuf::from(path);
    }
    let vault = vault_path();
    let name = vault
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.capabilities.json"))
        .unwrap_or_else(|| "skarbiec.vault.capabilities.json".to_string());
    vault.with_file_name(name)
}

/// The one path the broker resolves resources through. `route_table` reads and writes
/// exactly this file, so an operator's table is never written where nothing looks
/// for it -- a table beside the vault while the broker reads beside its state
/// file resolves nothing and says nothing about why.
pub(in crate::access) fn routes_path() -> PathBuf {
    if let Ok(path) = std::env::var("SKARBIEC_CAPABILITY_ROUTES_FILE") {
        return PathBuf::from(path);
    }
    state_path().with_file_name("capability-routes.json")
}

pub(in crate::access::capability) fn now_epoch() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

pub(in crate::access) fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub(in crate::access::capability) fn load_state() -> Result<Value> {
    let path = state_path();
    if !path.exists() {
        return Ok(json!({"version": 1, "capabilities": {}, "nonces": {}}));
    }
    let raw = fs::read_to_string(&path).context("read capability state")?;
    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(original) => {
            // Older writers could leave two complete snapshots concatenated
            // after an interrupted replacement. Capabilities are short-lived,
            // so the newest complete snapshot is safer than disabling every
            // provider indefinitely. Preserve the bytes before repairing them.
            let complete: Vec<Value> = serde_json::Deserializer::from_str(&raw)
                .into_iter::<Value>()
                .map_while(Result::ok)
                .collect();
            let Some(recovered) = complete.last().cloned() else {
                return Err(original).context("parse capability state");
            };
            let backup = path.with_extension(format!("json.corrupt-{}", std::process::id()));
            fs::copy(&path, &backup).with_context(|| {
                format!("back up corrupt capability state to {}", backup.display())
            })?;
            save_state(&recovered)
                .context("repair capability state from newest complete snapshot")?;
            recovered
        }
    };
    if parsed
        .get("capabilities")
        .and_then(Value::as_object)
        .is_none()
    {
        bail!("capability state is malformed");
    }
    Ok(parsed)
}

pub(in crate::access::capability) fn save_state(state: &Value) -> Result<()> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let staging = path.with_extension("json.staging");
    write_private_file(&staging, serde_json::to_string_pretty(state)?.as_bytes())?;
    fs::rename(&staging, &path)?;
    Ok(())
}
