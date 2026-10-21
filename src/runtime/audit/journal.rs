// The journal file itself: where it is, how a line is hashed onto the one
// before it, and the lock that keeps two writers from sharing a predecessor.

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The audit journal: `SKARBIEC_AUDIT_FILE`, else under the user's home as
/// `crate::core::home_dir` resolves it, never under the directory the process
/// started in.
pub(super) fn audit_path() -> PathBuf {
    if let Some(path) = crate::core::env::path("SKARBIEC_AUDIT_FILE") {
        return path;
    }
    crate::core::home_dir().join(".local/state/skarbiec/audit.jsonl")
}

/// UTC now, as the journal writes it: RFC 3339 with the fraction of the
/// second. It fails only for a clock past the year 9999, which no audit line
/// can carry: that is a broken host, said as such, never an empty stamp.
pub(super) fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("the system clock is past the year 9999, which no audit line can carry")
}

/// Read and write for the owner alone (`S_IRUSR | S_IWUSR`), the mode every
/// journal file is created with.
// mode_t is u16 on macOS and u32 on Linux: the conversion is real on one and
// the identity on the other.
#[allow(clippy::useless_conversion)]
fn owner_only_file() -> u32 {
    u32::from(libc::S_IRUSR | libc::S_IWUSR)
}

/// Read, write and search for the owner alone (`S_IRWXU`), the mode of the
/// journal's directory.
#[allow(clippy::useless_conversion)]
fn owner_only_directory() -> u32 {
    u32::from(libc::S_IRWXU)
}

pub(super) fn lines() -> Result<Vec<Value>> {
    let (entries, malformed) = lines_with_faults()?;
    if let Some(fault) = malformed.first() {
        anyhow::bail!(
            "audit journal {} holds a line that is not JSON: {fault}",
            audit_path().display()
        );
    }
    Ok(entries)
}

/// Every parseable line, plus the ones that are not.
///
/// A single malformed line used to end the whole read, which is the failure
/// an audit surface must not have: `verify-chain` refused a journal of two
/// million entries over one interleaved write and named neither the line nor
/// the reason. The scan the chain report documents does not stop at the first
/// fault, so the reader it is built on cannot either.
pub(super) fn lines_with_faults() -> Result<(Vec<Value>, Vec<Value>)> {
    let path = audit_path();
    let Some(body) = crate::core::read_present(&path, "audit journal")? else {
        return Ok((Vec::new(), Vec::new()));
    };
    let mut out = Vec::new();
    let mut malformed = Vec::new();
    // Lines are numbered from one, as an editor shows them.
    for (line_number, line) in (std::num::NonZeroUsize::MIN.get()..).zip(body.lines()) {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(line) {
            Ok(entry) => out.push(entry),
            Err(error) => malformed.push(json!({
                "line": line_number,
                "error": error.to_string(),
            })),
        }
    }
    Ok((out, malformed))
}

// The material each line's hash covers: previous hash + the line's own fields.
pub(super) fn digest_input(prev: &str, at: &str, op: &str, extra: &Value) -> String {
    format!("{prev}|{at}|{op}|{extra}")
}

/// Read only the journal's tail: the hash of the last complete line. Seeks to
/// the final window instead of parsing the whole file on every request.
pub(super) fn sha256_hex(input: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(input.as_bytes());
    format!("{:x}", digest.finalize())
}
pub(super) fn tail_hash() -> Result<String> {
    let path = audit_path();
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("open audit journal {}", path.display()));
        }
    };
    let len = file.metadata()?.len();
    let window = u64::from(u16::MAX);
    let skip = len.saturating_sub(window);
    file.seek(std::io::SeekFrom::Start(skip))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    // The window may open mid-line, so only its first line may be a cut
    // fragment. The last entry must parse and carry its hash, because chaining
    // onto an older hash or restarting the chain would fork the tamper-evident
    // journal.
    let cut = len > window;
    let mut lines = buf.lines().map(str::trim).filter(|line| !line.is_empty());
    if cut {
        lines.next();
    }
    let Some(last) = lines.next_back() else {
        if cut {
            bail!(
                "audit journal {} holds no complete entry in its last {window} bytes",
                path.display()
            );
        }
        // An empty journal: the chain starts here.
        return Ok(String::new());
    };
    let entry: Value = serde_json::from_str(last).with_context(|| {
        format!(
            "audit journal {} ends with a line that is not an entry",
            path.display()
        )
    })?;
    let hash = entry.get("hash").and_then(Value::as_str).with_context(|| {
        format!(
            "audit journal {}'s last entry carries no hash",
            path.display()
        )
    })?;
    Ok(hash.to_string())
}

/// The journal's cross-process critical section. The kernel owns lock lifetime:
/// process exit releases it, so no stale file, clock, or ownership stamp can
/// let two writers share one predecessor.
pub(super) struct AppendLock(File);

impl Drop for AppendLock {
    fn drop(&mut self) {
        // Closing the file releases the lock as well, so a failed unlock
        // loses nothing; it is still said rather than dropped unseen.
        if let Err(error) = self.0.unlock() {
            eprintln!("skarbiec: audit journal lock was not released explicitly: {error}");
        }
    }
}

pub(super) fn acquire_append_lock(path: &Path) -> Result<AppendLock> {
    let lock_path = path.with_extension("append.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(owner_only_file())
        .open(&lock_path)
        .with_context(|| format!("open audit journal lock {}", lock_path.display()))?;
    // The kernel queues this process until the holder releases the lock or
    // exits; the wait is announced on stderr, and a failure to lock is the
    // error itself.
    stado_wait::blocking(
        stado_wait::Kind::Lock,
        "the audit journal lock",
        lock_path.display(),
        || file.lock_exclusive(),
    )
    .with_context(|| format!("lock audit journal {}", lock_path.display()))?;
    Ok(AppendLock(file))
}

/// Parse only the journal's final `limit` entries, walking backwards in
/// widening windows, so the cost follows the size of the answer instead of
/// the size of the file. A dashboard asking for ten rows must not read
/// seventeen megabytes to get them.
pub(super) fn tail_lines(limit: usize) -> Result<Vec<Value>> {
    let path = audit_path();
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("open audit journal {}", path.display()));
        }
    };
    let length = file.metadata()?.len();
    let mut window = u64::from(u16::MAX);
    loop {
        // A window that does not reach the start of the file opens mid-file,
        // so its first line may be cut: it is left to the next, wider window.
        let from_start = window >= length;
        file.seek(std::io::SeekFrom::Start(length.saturating_sub(window)))?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)?;
        let mut lines = buffer
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty());
        if !from_start {
            lines.next();
        }
        let mut parsed: Vec<Value> = Vec::new();
        for line in lines {
            parsed.push(serde_json::from_str(line).context("audit line is not JSON")?);
        }
        if parsed.len() >= limit || from_start {
            let excess = parsed.len().saturating_sub(limit);
            return Ok(parsed.split_off(excess));
        }
        // Each wider window reads as much again as the last one did.
        window = window.saturating_add(window);
    }
}

/// Audit completion is part of the operation, not best-effort background work.
/// The bounded HTTP executor supplies backpressure; this call returns only
/// after the journal entry is durable.
pub fn append(op: &str, extra: &Value) -> Result<()> {
    append_sync(op, extra)
}

/// The journal opened for appending, created owner-only when it is new.
pub(super) fn open_for_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(owner_only_file())
        .open(path)
}

/// Append one hash-chained entry inline. `prev` is the previous line's hash
/// (empty for the genesis line). Never records any stored value.
///
/// The predecessor is read from the journal inside the lock and never from a
/// cached copy. Caching it is what turns one lost race into permanent damage:
/// the loser keeps appending against a hash that stopped being the tail.
pub fn append_sync(op: &str, extra: &Value) -> Result<()> {
    let path = audit_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create audit directory {}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(owner_only_directory()))
            .with_context(|| format!("protect audit directory {}", parent.display()))?;
    }
    let _lock = acquire_append_lock(&path)?;
    let prev = tail_hash()?;
    let at = now_iso();
    let hash = sha256_hex(&digest_input(&prev, &at, op, extra));
    let entry = json!({"at": at, "op": op, "extra": extra, "prev": prev, "hash": hash});
    let fresh = !path.exists();
    let mut file = open_for_append(&path)?;
    writeln!(file, "{entry}")?;
    file.sync_data()?;
    if fresh {
        File::open(path.parent().context("audit path has no parent")?)?.sync_all()?;
    }
    Ok(())
}
