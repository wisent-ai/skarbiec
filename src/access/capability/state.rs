// Where a capability and its spent nonces are recorded, and the lock that
// keeps two redemptions from spending the same use.

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde_json::Value;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::journal;
use crate::core::vault_path;

/// The kernel owns this lock's lifetime: process exit releases it, so a
/// crashed holder never leaves a stale lock behind.
pub(in crate::access::capability) struct StateLock(File);

impl Drop for StateLock {
    fn drop(&mut self) {
        // Closing the file releases the lock as well, so a failed unlock
        // loses nothing; it is still said rather than dropped unseen.
        if let Err(error) = self.0.unlock() {
            eprintln!("skarbiec: capability state lock was not released explicitly: {error}");
        }
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
    // exits; the wait is announced on stderr, and a failure to lock is the
    // error itself.
    stado_wait::blocking(
        stado_wait::Kind::Lock,
        "the capability state lock",
        path.display(),
        || file.lock_exclusive(),
    )
    .context("lock capability state")?;
    Ok(StateLock(file))
}

/// Where the capability records live: `SKARBIEC_CAPABILITY_FILE` when an
/// operator names one, and otherwise the vault's own path with
/// `.capabilities.json` beside it, so a second vault never shares the first
/// one's records.
pub(in crate::access::capability) fn state_path() -> PathBuf {
    if let Some(path) = crate::core::env::path("SKARBIEC_CAPABILITY_FILE") {
        return path;
    }
    // The suffix is appended to the vault's own path, so a vault whose name
    // is not UTF-8 still gets its records beside it.
    let mut records = vault_path().into_os_string();
    records.push(".capabilities.json");
    PathBuf::from(records)
}

/// The one path the broker resolves resources through. `route_table` reads and writes
/// exactly this file, so an operator's table is never written where nothing looks
/// for it -- a table beside the vault while the broker reads beside its state
/// file resolves nothing and says nothing about why.
pub(in crate::access) fn routes_path() -> PathBuf {
    if let Some(path) = crate::core::env::path("SKARBIEC_CAPABILITY_ROUTES_FILE") {
        return path;
    }
    state_path().with_file_name("capability-routes.json")
}

/// Now, by the one unsigned clock reader capabilities and grants share.
pub(in crate::access::capability) fn now_epoch() -> Result<u64> {
    crate::core::clock::epoch_seconds()
}

/// Write `bytes` to a file only its owner can read. The file is created
/// owner-only, so the bytes are never readable by others between the write
/// and a permission change, and a file that already existed is narrowed
/// before anything is written into it.
pub(in crate::access) fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mode = crate::core::vault::private_file_mode()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .with_context(|| format!("make {} owner-only", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("flush {} to disk", path.display()))
}

/// Put the staged file `staging` in place as `path` and flush the directory
/// holding it, so the replacement survives a crash; a write is reported done
/// only once both happened, and a flush that fails is the error.
pub(in crate::access) fn install_private_file(staging: &Path, path: &Path) -> Result<()> {
    fs::rename(staging, path).with_context(|| format!("install {}", path.display()))?;
    let parent = path
        .parent()
        .with_context(|| format!("{} has no directory to flush", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| {
            format!(
                "flush the directory {} after installing {}",
                parent.display(),
                path.display()
            )
        })
}

/// The capability state the journal replays to, without the capabilities
/// that can no longer be redeemed (`forget_stale`). Bytes after the last
/// complete value (an append or replacement interrupted mid-write) are kept
/// beside the journal and the journal is replaced by what replayed, and
/// that is said; a journal with no complete value at all is refused.
pub(in crate::access::capability) fn load_state() -> Result<Value> {
    let path = state_path();
    let Some(raw) = crate::core::read_present(&path, "capability state")? else {
        return Ok(journal::empty());
    };
    let replayed = journal::replay(&raw)?;
    let mut state = replayed.state;
    if let Some(error) = replayed.trailing {
        if !replayed.complete {
            return Err(error).context("parse capability state");
        }
        let backup = path.with_extension(format!("json.corrupt-{}", std::process::id()));
        fs::copy(&path, &backup)
            .with_context(|| format!("back up corrupt capability state to {}", backup.display()))?;
        save_state(&state).context("repair capability state from the values that replay")?;
        eprintln!(
            "skarbiec: capability state {} ends in bytes that do not parse ({error}); kept what \
             replays before them, original bytes in {}",
            path.display(),
            backup.display()
        );
    }
    forget_stale(&mut state, now_epoch()?)?;
    Ok(state)
}

/// Drop every capability that can no longer be redeemed -- past its expiry,
/// or no longer `issued` because its uses are spent or it was cancelled --
/// and every nonce whose capability is gone. Redemption refuses a capability
/// it does not find exactly as it refuses one that is not `issued`, so a
/// dropped record changes no answer, and a nonce matters only while its
/// capability can still be redeemed; the audit log keeps what was issued,
/// redeemed and cancelled. The state every request reads and rewrites
/// therefore grows with the capabilities that can still be redeemed, not
/// with every one ever issued.
///
/// Nonces are matched against a set of the live capability ids, so the work
/// grows with the number of nonces, not with their product with the
/// capabilities.
fn forget_stale(state: &mut Value, now: u64) -> Result<()> {
    let Some(capabilities) = state["capabilities"].as_object_mut() else {
        bail!("capability state is malformed: capabilities is not an object");
    };
    capabilities.retain(|_, record| {
        let unexpired = record
            .get("expires_at")
            .and_then(Value::as_u64)
            .is_some_and(|until| until > now);
        unexpired && record.get("state").and_then(Value::as_str) == Some("issued")
    });
    let live: HashSet<String> = capabilities.keys().cloned().collect();
    if let Some(nonces) = state["nonces"].as_object_mut() {
        nonces.retain(|key, _| {
            key.split_once(':')
                .is_some_and(|(capability, _)| live.contains(capability))
        });
    }
    Ok(())
}

/// Replace the journal with one snapshot of `state`.
pub(in crate::access::capability) fn save_state(state: &Value) -> Result<()> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let staging = path.with_extension("json.staging");
    let mut snapshot = serde_json::to_vec(state)?;
    snapshot.push(b'\n');
    write_private_file(&staging, &snapshot)?;
    install_private_file(&staging, &path)
}

/// Record what changed in `state` for `capability_id`: its record as
/// `state` holds it, and the nonce `nonce` names when one was seen, appended
/// to the journal, so the write is the size of that one entry. The caller
/// holds the state lock. A journal whose dead entries outweigh the live state
/// is then replaced by one snapshot of it (`journal::outweighed`).
pub(in crate::access::capability) fn save_entry(
    state: &Value,
    capability_id: &str,
    nonce: Option<&str>,
) -> Result<()> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    journal::append(&path, &journal::entries(state, capability_id, nonce)?)?;
    if journal::outweighed(&path, state)? {
        save_state(state)?;
    }
    Ok(())
}
