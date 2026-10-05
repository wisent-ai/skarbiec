// Where a capability and its spent nonces are recorded, and the lock that
// keeps two redemptions from spending the same use.

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::core::vault_path;

/// The kernel owns this lock's lifetime: process exit releases it, so a
/// crashed holder never leaves a stale lock behind.
pub(in crate::access::capability) struct StateLock(File);

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub(in crate::access::capability) fn acquire_state_lock() -> Result<StateLock> {
    let path = state_path().with_extension("json.lock");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("open capability state lock {}", path.display()))?;
    // The kernel queues this process until the holder releases the lock or
    // exits; a failure to lock is the error itself.
    file.lock_exclusive().context("lock capability state")?;
    Ok(StateLock(file))
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
    let mut parsed = parsed;
    forget_stale(&mut parsed, now_epoch()?);
    Ok(parsed)
}

/// Drop every capability record past its expiry, and every nonce whose
/// capability is gone. A nonce is refused for as long as the capability it
/// was used with can still be redeemed, which is exactly as long as replay
/// matters; after that nothing reads either, and the audit log keeps what was
/// issued and redeemed. Without this the broker Brama runs on the vault owner
/// would read and rewrite every capability ever issued on each request, and
/// its state grows to GiBs within a day or two.
fn forget_stale(state: &mut Value, now: u64) {
    if let Some(capabilities) = state["capabilities"].as_object_mut() {
        capabilities.retain(|_, record| {
            record.get("expires_at").and_then(Value::as_u64).is_some_and(|until| until > now)
        });
    }
    let live: Vec<String> = state["capabilities"]
        .as_object()
        .map(|capabilities| capabilities.keys().cloned().collect())
        .unwrap_or_default();
    if let Some(nonces) = state["nonces"].as_object_mut() {
        nonces.retain(|key, _| {
            key.split_once(':').is_some_and(|(capability, _)| live.iter().any(|id| id == capability))
        });
    }
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
