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
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::core::vault_path;

/// Owner read and write, nothing for group or other: the same mode the
/// donation inbox and the capability state are kept at.
fn owner_only() -> u32 {
    u32::from(libc::S_IRUSR | libc::S_IWUSR)
}

/// The octets of a UUID and the layout of version 4 (random) ones:
/// <https://www.rfc-editor.org/rfc/rfc9562#section-5.4>.
const UUID_OCTETS: usize = 16;
/// <https://www.rfc-editor.org/rfc/rfc9562#section-5.4>: octet holding the version.
const VERSION_OCTET: usize = 6;
/// <https://www.rfc-editor.org/rfc/rfc9562#section-5.4>: version 4 in the high nibble.
const VERSION_BITS: u8 = 0x40;
/// <https://www.rfc-editor.org/rfc/rfc9562#section-5.4>: the random low nibble kept.
const VERSION_KEPT: u8 = 0x0f;
/// <https://www.rfc-editor.org/rfc/rfc9562#section-5.4>: octet holding the variant.
const VARIANT_OCTET: usize = 8;
/// <https://www.rfc-editor.org/rfc/rfc9562#section-4.1>: variant bits `10`.
const VARIANT_BITS: u8 = 0x80;
/// <https://www.rfc-editor.org/rfc/rfc9562#section-4.1>: the random bits kept.
const VARIANT_KEPT: u8 = 0x3f;
/// <https://www.rfc-editor.org/rfc/rfc9562#section-4>: octets per hyphenated group.
const GROUP_OCTETS: &[usize] = &[4, 2, 2, 2, 6];

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
        // The kernel releases the lock when the file closes right after;
        // an unlock that fails is still said.
        if let Err(error) = self.0.unlock() {
            eprintln!("request register lock could not be released before closing: {error}");
        }
    }
}

pub(super) fn lock() -> Result<RegisterLock> {
    let path = register_path().with_extension("json.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(owner_only())
        .open(&path)
        .with_context(|| format!("open request register lock {}", path.display()))?;
    let place = path.display().to_string();
    stado_wait::blocking(
        stado_wait::Kind::Lock,
        "the request register lock",
        place,
        || file.lock_exclusive(),
    )
    .context("lock request register")?;
    Ok(RegisterLock(file))
}

pub(super) fn load() -> Result<Value> {
    let path = register_path();
    let body = match fs::read_to_string(&path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({"requests": []}))
        }
        Err(error) => {
            return Err(error).with_context(|| format!("read request register {}", path.display()))
        }
    };
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
        .mode(owner_only())
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(owner_only()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Tell a running watcher the register changed. Nobody watching is the
/// ordinary case and not a failure: the FIFO is absent, or present with no
/// reader (ENXIO), or already holds an unread wake (EAGAIN). Any other
/// failure is said, since a watcher would then sit on a stale register.
fn wake() {
    let fifo = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(wake_path());
    let mut fifo = match fifo {
        Ok(fifo) => fifo,
        Err(error)
            if error.kind() == ErrorKind::NotFound || error.raw_os_error() == Some(libc::ENXIO) =>
        {
            return
        }
        Err(error) => {
            eprintln!(
                "request watcher could not be woken: {}: {error}",
                wake_path().display()
            );
            return;
        }
    };
    match fifo.write_all(b"\n") {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        Err(error) => eprintln!(
            "request watcher could not be woken: {}: {error}",
            wake_path().display()
        ),
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

/// The text `key` holds in a register record, or the refusal naming the
/// record and the key it lacks: a record missing one is damaged, and is
/// never read as an empty answer.
pub(super) fn text<'a>(record: &'a Value, key: &str) -> Result<&'a str> {
    record
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("access request record holds no text {key}: {record}"))
}

/// A request id: a version 4 UUID in lowercase, the shape Las accepts as
/// `request_id` and redemption accepts as an authorization id.
pub(super) fn new_id() -> Result<String> {
    let mut octets = Vec::with_capacity(UUID_OCTETS);
    File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .take(u64::try_from(UUID_OCTETS).context("a UUID's length does not fit a read length")?)
        .read_to_end(&mut octets)
        .context("read /dev/urandom")?;
    if octets.len() != UUID_OCTETS {
        bail!(
            "/dev/urandom gave {} of the {UUID_OCTETS} octets a request id needs",
            octets.len()
        );
    }
    octets[VERSION_OCTET] = (octets[VERSION_OCTET] & VERSION_KEPT) | VERSION_BITS;
    octets[VARIANT_OCTET] = (octets[VARIANT_OCTET] & VARIANT_KEPT) | VARIANT_BITS;
    let mut groups = Vec::new();
    let mut rest = octets.as_slice();
    for width in GROUP_OCTETS {
        let (group, after) = rest.split_at(*width);
        groups.push(
            group
                .iter()
                .map(|octet| format!("{octet:02x}"))
                .collect::<String>(),
        );
        rest = after;
    }
    Ok(groups.join("-"))
}
