// The access request register: `<vault>.requests.json`, owner-only, beside
// the vault like the donation inbox (core/inbox.rs). It holds what was asked,
// by whom, and every decision a person took on it; the grant itself is still
// written by the grant leaves, so the register never holds a bearer.
//
// Writers serialize on a kernel lock beside the file, and every change wakes a
// running `request watch` through a FIFO beside it, so the watcher blocks on
// the next change instead of re-reading the file on a clock.

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::core::vault_path;

/// Owner read and write, nothing for group or other (POSIX mode 0600): the
/// same mode the donation inbox and the capability state are kept at.
const OWNER_ONLY: u32 = 0o600;

pub(super) fn register_path() -> PathBuf {
    vault_path().with_extension("requests.json")
}

/// The FIFO a watcher reads and every register writer pokes.
pub(super) fn wake_path() -> PathBuf {
    vault_path().with_extension("requests.wake")
}

/// Where the bearer of a standing grant issued for one request is kept,
/// owner-only, so neither an answer nor a log ever carries it.
pub(super) fn token_path(request_id: &str) -> PathBuf {
    vault_path().with_extension(format!("request-{request_id}.token"))
}

/// Held for one read-modify-write of the register; the kernel releases it
/// when the process exits, so a crashed writer leaves nothing stale.
pub(super) struct RegisterLock(File);

impl Drop for RegisterLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub(super) fn lock() -> Result<RegisterLock> {
    let path = register_path().with_extension("json.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(OWNER_ONLY)
        .open(&path)
        .with_context(|| format!("open request register lock {}", path.display()))?;
    file.lock_exclusive().context("lock request register")?;
    Ok(RegisterLock(file))
}

pub(super) fn load() -> Result<Value> {
    let path = register_path();
    if !path.exists() {
        return Ok(json!({"requests": []}));
    }
    let body = fs::read_to_string(&path)
        .with_context(|| format!("read request register {}", path.display()))?;
    let doc: Value = serde_json::from_str(&body)
        .with_context(|| format!("parse request register {}", path.display()))?;
    if doc.get("requests").and_then(Value::as_array).is_none() {
        bail!("request register {} has no requests list", path.display());
    }
    Ok(doc)
}

/// Replace the register atomically at owner-only mode, then wake a watcher.
pub(super) fn save(doc: &Value, _held: &RegisterLock) -> Result<()> {
    let path = register_path();
    let staging = path.with_extension("json.staging");
    write_private(&staging, serde_json::to_string_pretty(doc)?.as_bytes())?;
    fs::rename(&staging, &path)
        .with_context(|| format!("replace request register {}", path.display()))?;
    wake();
    Ok(())
}

pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(OWNER_ONLY)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Tell a running watcher the register changed. Nobody watching is the
/// ordinary case and not a failure: the FIFO is absent, or present with no
/// reader (ENXIO), or already holds an unread wake (EAGAIN).
fn wake() {
    if let Ok(mut fifo) = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(wake_path())
    {
        let _ = fifo.write_all(b"\n");
    }
}

pub(super) fn requests(doc: &Value) -> impl Iterator<Item = &Value> {
    doc.get("requests")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

pub(super) fn find<'a>(doc: &'a mut Value, id: &str) -> Result<&'a mut Value> {
    doc.get_mut("requests")
        .and_then(Value::as_array_mut)
        .context("request register has no requests list")?
        .iter_mut()
        .find(|request| request.get("id").and_then(Value::as_str) == Some(id))
        .with_context(|| format!("no access request {id}"))
}

pub(super) fn get(doc: &Value, id: &str) -> Result<Value> {
    requests(doc)
        .find(|request| request.get("id").and_then(Value::as_str) == Some(id))
        .cloned()
        .with_context(|| format!("no access request {id}"))
}

pub(super) fn text<'a>(record: &'a Value, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// A request id: a version 4 UUID in lowercase (RFC 9562 section 5.4), the
/// shape Las accepts as `request_id` and redemption accepts as an
/// authorization id.
pub(super) fn new_id() -> Result<String> {
    let hex = crate::core::crypto::random_token()?;
    let digits: Vec<char> = hex.chars().collect();
    // RFC 9562 section 4: 8-4-4-4-12 hex digits; the 13th digit is the
    // version (4) and the top two bits of the 17th are the variant (10).
    let group = |from: usize, to: usize| digits[from..to].iter().collect::<String>();
    let variant = digits[16]
        .to_digit(16)
        .map(|value| (value & 0x3) | 0x8)
        .and_then(|value| char::from_digit(value, 16))
        .context("random token is not hex")?;
    Ok(format!(
        "{}-{}-4{}-{}{}-{}",
        group(0, 8),
        group(8, 12),
        group(13, 16),
        variant,
        group(17, 20),
        group(20, 32)
    ))
}
