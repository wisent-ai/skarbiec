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
/// `crate::core::home_dir` resolves it. An unset HOME no longer puts the
/// journal under whatever directory the process started in.
pub(super) fn audit_path() -> PathBuf {
    if let Some(path) = crate::core::env::path("SKARBIEC_AUDIT_FILE") {
        return path;
    }
    crate::core::home_dir().join(".local/state/skarbiec/audit.jsonl")
}

pub(super) fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

pub(super) fn lines() -> Result<Vec<Value>> {
    let (entries, malformed) = lines_with_faults()?;
    if let Some(fault) = malformed.first() {
        let line = fault
            .get("line")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let detail = fault
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unparseable");
        anyhow::bail!("audit line {line} is not JSON: {detail}");
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
    if !path.exists() {
        return Ok((Vec::new(), Vec::new()));
    }
    let body = std::fs::read_to_string(&path)?;
    let mut out = Vec::new();
    let mut malformed = Vec::new();
    for (offset, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(line) {
            Ok(entry) => out.push(entry),
            Err(error) => malformed.push(json!({
                "line": offset.saturating_add(1),
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
    if !path.exists() {
        return Ok(String::new());
    }
    let mut file = std::fs::File::open(&path)?;
    let len = file.metadata()?.len();
    let window = u64::try_from(usize::from(u16::MAX)).unwrap_or(u64::MAX);
    let skip = len.saturating_sub(window);
    file.seek(std::io::SeekFrom::Start(skip))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    // The window may open mid-line, so only its first line may be a cut
    // fragment. The last entry must parse and carry its hash: walking back
    // past a damaged last line chained the next entry onto an older hash, and
    // an entry without one restarted the chain - both silently forked the
    // tamper-evident journal.
    let cut = len > window;
    let mut lines = buf.lines().map(str::trim).filter(|line| !line.is_empty());
    if cut {
        lines.next();
    }
    let Some(last) = lines.last() else {
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
        let _ = self.0.unlock();
    }
}

pub(super) fn acquire_append_lock(path: &Path) -> Result<AppendLock> {
    let lock_path = path.with_extension("append.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .with_context(|| format!("open audit journal lock {}", lock_path.display()))?;
    file.lock_exclusive()
        .with_context(|| format!("lock audit journal {}", lock_path.display()))?;
    Ok(AppendLock(file))
}

/// Parse only the journal's final `limit` entries, walking backwards in
/// widening windows, so the cost follows the size of the answer instead of
/// the size of the file. A dashboard asking for ten rows must not read
/// seventeen megabytes to get them.
pub(super) fn tail_lines(limit: usize) -> Result<Vec<Value>> {
    let path = audit_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut file = std::fs::File::open(&path)?;
    let length = file.metadata()?.len();
    let mut window = u64::try_from(usize::from(u16::MAX))?;
    let growth: u64 = 2;
    loop {
        let start = length.saturating_sub(window);
        file.seek(std::io::SeekFrom::Start(start))?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)?;
        let mut parsed: Vec<Value> = Vec::new();
        for line in buffer.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str(trimmed) {
                Ok(value) => parsed.push(value),
                // A window opened mid-file cuts its first line; every later
                // one is whole, so only that leading fragment may be dropped.
                Err(_) if start > u64::MIN && parsed.is_empty() => continue,
                Err(error) => return Err(error).context("audit line is not JSON"),
            }
        }
        if parsed.len() >= limit || start == u64::MIN {
            let excess = parsed.len().saturating_sub(limit);
            return Ok(parsed.split_off(excess));
        }
        window = window.saturating_mul(growth);
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
        .mode(0o600)
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
        let private_mode = 0o700;
        fs::set_permissions(parent, fs::Permissions::from_mode(private_mode))
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

/// Every loopback port a `unit-retired` entry says a retired unit answered on.
///
/// A host the one process converged before it kept those ports beside the
/// vault has them here and nowhere else. Only lines naming that operation are
/// parsed, so a long journal costs one pass of reading, once per host. A
/// journal that does not exist names no port; one that cannot be read, or a
/// `unit-retired` line whose ports cannot be read, is the error, because the
/// ports it drops would go unanswered with nothing said.
pub fn retired_ports() -> Result<std::collections::BTreeSet<u16>> {
    use std::io::BufRead;
    let path = audit_path();
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(std::collections::BTreeSet::new());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("open audit journal {}", path.display()));
        }
    };
    let mut ports = std::collections::BTreeSet::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line.with_context(|| format!("read audit journal {}", path.display()))?;
        if !line.contains("\"op\":\"unit-retired\"") {
            continue;
        }
        let entry: Value = serde_json::from_str(&line).with_context(|| {
            format!(
                "audit journal {} holds a unit-retired line that is not JSON: {line}",
                path.display()
            )
        })?;
        let listed = entry["extra"]["ports"].as_array().with_context(|| {
            format!(
                "audit journal {} holds a unit-retired entry with no list of ports: {line}",
                path.display()
            )
        })?;
        for port in listed {
            let answered = port
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .with_context(|| {
                    format!(
                        "audit journal {} holds a unit-retired entry whose {port} is not a port: {line}",
                        path.display()
                    )
                })?;
            ports.insert(answered);
        }
    }
    Ok(ports)
}
