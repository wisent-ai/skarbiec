// Tamper-evident audit journal. Each line records at/op/extra plus the hash of
// the previous line, forming a chain: any retroactive edit breaks every hash
// after it, which `verify-chain` detects. Values are never journalled — only
// operation names and non-sensitive identifiers.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Seek as _, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use crate::core::crypto;

// Appends are serialized across every process sharing one journal. The chain
// is read-modify-write, so two writers that each read the same tail produce
// two lines claiming one predecessor. That is not hypothetical: it happened
// here on 2026-07-30T23:16:21Z, when a mutating command and an HTTP read
// raced, and a single such line was enough to make `verify-chain` refuse the
// whole record. A process-wide mutex cannot see the other process, so the
// critical section is a lock file beside the journal and the predecessor is
// always re-read from disk inside it. High-frequency read paths enqueue
// entries on a channel that one worker thread journals; mutating operations
// call `append_sync` so their evidence is durable before the response
// returns.
static QUEUE: LazyLock<std::sync::mpsc::Sender<(String, Value)>> = LazyLock::new(|| {
    let (tx, rx) = std::sync::mpsc::channel::<(String, Value)>();
    std::thread::spawn(move || {
        while let Ok((op, extra)) = rx.recv() {
            if let Err(error) = append_sync(&op, &extra) {
                eprintln!("audit append failed: {error}");
            }
        }
    });
    tx
});

fn audit_path() -> PathBuf {
    if let Ok(p) = std::env::var("SKARBIEC_AUDIT_FILE") {
        return PathBuf::from(p);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local/state/skarbiec/audit.jsonl")
}

fn now_iso() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn lines() -> Result<Vec<Value>> {
    let path = audit_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let body = std::fs::read_to_string(&path)?;
    let mut out = Vec::new();
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(line).context("audit line is not JSON")?);
    }
    Ok(out)
}

// The material each line's hash covers: previous hash + the line's own fields.
fn digest_input(prev: &str, at: &str, op: &str, extra: &Value) -> String {
    format!("{prev}|{at}|{op}|{extra}")
}

/// Read only the journal's tail: the hash of the last complete line. Seeks to
/// the final window instead of parsing the whole file on every request.
fn tail_hash() -> Result<String> {
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
    // The window may open mid-line; walk back to the last line that parses as
    // a journal entry rather than trusting the first '{' after the cut.
    for line in buf.lines().rev() {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<Value>(trimmed) {
            return Ok(entry
                .get("hash")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string());
        }
    }
    Ok(String::new())
}

/// The journal's cross-process critical section. Held for one tail read and
/// one append - milliseconds - and released on drop, including on the error
/// paths, because a lock leaked by a failed append would stall every later
/// writer until it aged out.
///
/// The holder carries a stamp and releases only the lock still bearing it. An
/// unconditional remove is what let two writers share one critical section: a
/// lock aged past the abandonment window is deleted and recreated by the next
/// writer, so the slow original's drop deleted *that* writer's lock and a third
/// writer walked in beside it. Both then read one tail and appended two lines
/// claiming a single predecessor. The journal on this workstation carries that
/// shape twice, at 2026-08-10T03:55:23Z and 2026-08-10T17:08:42Z, each time an
/// `mcp-serve` line and an `http-item-read` line sharing a `prev`.
struct AppendLock {
    path: PathBuf,
    stamp: String,
}

impl Drop for AppendLock {
    fn drop(&mut self) {
        let ours = fs::read_to_string(&self.path)
            .map(|held| held.trim() == self.stamp)
            .unwrap_or(false);
        if ours {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// A holder that died leaves a file nobody removes. Appends take milliseconds,
/// so a lock file older than this was abandoned rather than held, and waiting
/// on it would be waiting forever.
fn lock_is_abandoned(lock_path: &Path) -> bool {
    let Ok(seconds) = "30".parse::<u64>() else {
        return false;
    };
    fs::metadata(lock_path)
        .and_then(|metadata| metadata.modified())
        .map(|modified| modified.elapsed().unwrap_or_default() > Duration::from_secs(seconds))
        .unwrap_or(false)
}

fn acquire_append_lock(path: &Path) -> Result<AppendLock> {
    let lock_path = path.with_extension("append.lock");
    let deadline = Instant::now() + Duration::from_secs("5".parse()?);
    let pause = Duration::from_millis("5".parse()?);
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(mut file) => {
                // The stamp is written and flushed before the guard exists, so a
                // holder never claims a lock whose contents it failed to record.
                // A write that fails leaves an unstamped file, which no drop will
                // remove and which the abandonment window clears - slower than a
                // leak-free release, and safe, which the alternative was not.
                let stamp = format!("{}:{}", std::process::id(), crypto::random_token()?);
                writeln!(file, "{stamp}")?;
                file.sync_all()?;
                return Ok(AppendLock {
                    path: lock_path,
                    stamp,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if lock_is_abandoned(&lock_path) {
                    let _ = fs::remove_file(&lock_path);
                    continue;
                }
                if Instant::now() >= deadline {
                    anyhow::bail!(
                        "audit journal lock {} is still held; no entry was written",
                        lock_path.display()
                    );
                }
                std::thread::sleep(pause);
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("open audit journal lock {}", lock_path.display()))
            }
        }
    }
}

/// Parse only the journal's final `limit` entries, walking backwards in
/// widening windows, so the cost follows the size of the answer instead of
/// the size of the file. A dashboard asking for ten rows must not read
/// seventeen megabytes to get them.
fn tail_lines(limit: usize) -> Result<Vec<Value>> {
    let path = audit_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut file = std::fs::File::open(&path)?;
    let length = file.metadata()?.len();
    let mut window = u64::try_from(usize::from(u16::MAX))?;
    let growth: u64 = "2".parse()?;
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

/// Queue one entry for the background journal worker. Read paths use this so
/// the hash-chain serialization (two subprocess spawns per line) never lands
/// on the consumer's response latency. Falls back to a synchronous append
/// when the worker is gone, so evidence is never silently dropped.
pub fn append(op: &str, extra: &Value) -> Result<()> {
    match QUEUE.send((op.to_string(), extra.clone())) {
        Ok(()) => Ok(()),
        Err(std::sync::mpsc::SendError((op, extra))) => append_sync(&op, &extra),
    }
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
        let private_mode = u32::from_str_radix("700", "8".parse()?)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(private_mode))
            .with_context(|| format!("protect audit directory {}", parent.display()))?;
    }
    let _lock = acquire_append_lock(&path)?;
    let prev = tail_hash()?;
    let at = now_iso();
    let hash = crypto::sha256_hex(&digest_input(&prev, &at, op, extra))?;
    let entry = json!({"at": at, "op": op, "extra": extra, "prev": prev, "hash": hash});
    let fresh = !path.exists();
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{entry}")?;
    if fresh {
        Command::new("chmod").arg("600").arg(&path).status().ok();
    }
    Ok(())
}

/// Verify the journal's hash chain, and say which journal was verified.
///
/// Naming the file is not decoration. This binary's default path and the path
/// Stado hands its callers are different files, so a bare `intact: true` over
/// a nearly empty default journal reads exactly like a clean bill of health
/// for the vault actually in use. Measured here: the default carried 67
/// entries while the journal in service carried 74,835.
///
/// Two properties are checked, they fail for different reasons, and they cost
/// wildly different amounts:
///
/// - **Linkage** - each line's recorded predecessor is the line before it.
///   Two string comparisons, no hashing, so it always covers the whole
///   journal. This is the property a second writer breaks, and the one that
///   actually broke here on 2026-07-30.
/// - **Digest** - the line's own fields still hash to the hash it carries.
///   This is the property a retroactive edit breaks, and it costs one
///   `shasum` process per line: 74,859 entries take about fifteen minutes.
///   `--tail N` bounds it to the newest N lines.
///
/// Neither scan stops at the first fault. Stopping is what let one raced
/// append in July hide the seventy-two thousand well-formed entries written
/// after it - the opposite of what an audit surface is for.
pub fn chain_report(flags: &HashMap<String, String>) -> Result<Value> {
    let entries = lines()?;
    let one: usize = "1".parse()?;
    let total = entries.len();
    let digests_from = match flags.get("tail") {
        Some(raw) => {
            let requested: usize = raw.parse().context("--tail must be a whole number")?;
            if requested < one {
                anyhow::bail!("--tail must be at least one");
            }
            total.saturating_sub(requested)
        }
        None => usize::MIN,
    };
    let mut faults: Vec<Value> = Vec::new();
    let mut linked = usize::MIN;
    let mut digested = usize::MIN;
    let mut previous_hash = String::new();
    for (offset, entry) in entries.iter().enumerate() {
        let at = entry.get("at").and_then(Value::as_str).unwrap_or("");
        let op = entry.get("op").and_then(Value::as_str).unwrap_or("");
        let stored_prev = entry.get("prev").and_then(Value::as_str).unwrap_or("");
        let stored_hash = entry.get("hash").and_then(Value::as_str).unwrap_or("");
        let line = offset.saturating_add(one);
        if stored_prev == previous_hash {
            linked = linked.saturating_add(one);
        } else {
            faults.push(json!({"line": line, "at": at, "op": op, "fault": "linkage"}));
        }
        if offset >= digests_from {
            let extra = entry.get("extra").cloned().unwrap_or(Value::Null);
            // Recomputed against the line's own recorded predecessor, so one
            // linkage fault does not cascade into every later digest.
            let recomputed = crypto::sha256_hex(&digest_input(stored_prev, at, op, &extra))?;
            if stored_hash == recomputed {
                digested = digested.saturating_add(one);
            } else {
                faults.push(json!({"line": line, "at": at, "op": op, "fault": "digest"}));
            }
        }
        previous_hash = stored_hash.to_string();
    }
    let broken_at = faults
        .first()
        .and_then(|fault| fault.get("at"))
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(json!({
        "journal": audit_path().display().to_string(),
        "entries": total,
        "linkage_checked": total,
        "linkage_verified": linked,
        "digests_checked": total.saturating_sub(digests_from),
        "digests_verified": digested,
        "intact": faults.is_empty(),
        "broken_at": broken_at,
        "faults": faults,
    }))
}

/// The journal, oldest first. `--limit N` returns only the final N, read from
/// the file's tail rather than parsed in full.
fn recent(flags: &HashMap<String, String>) -> Result<Vec<Value>> {
    let Some(raw) = flags.get("limit") else {
        return lines();
    };
    let limit: usize = raw.parse().context("--limit must be a whole number")?;
    if limit == usize::MIN {
        anyhow::bail!("--limit must be at least one");
    }
    tail_lines(limit)
}

fn query(flags: &HashMap<String, String>) -> Result<Value> {
    let limit: usize = flags
        .get("limit")
        .map(String::as_str)
        .unwrap_or("100")
        .parse()
        .context("--limit must be a positive integer")?;
    let maximum: usize = "10000".parse()?;
    if limit == usize::MIN || limit > maximum {
        anyhow::bail!("--limit must be between one and 10000");
    }
    let operation = flags.get("op").map(String::as_str);
    let consumer = flags.get("consumer").map(String::as_str);
    let item = flags.get("item").map(String::as_str);
    let since = flags.get("since").map(String::as_str);
    let until = flags.get("until").map(String::as_str);
    let mut entries: Vec<Value> = lines()?
        .into_iter()
        .filter(|entry| {
            let at = entry.get("at").and_then(Value::as_str).unwrap_or_default();
            let extra = entry.get("extra");
            operation.is_none_or(|value| entry.get("op").and_then(Value::as_str) == Some(value))
                && consumer.is_none_or(|value| {
                    extra
                        .and_then(|object| object.get("consumer"))
                        .and_then(Value::as_str)
                        == Some(value)
                })
                && item.is_none_or(|value| {
                    extra
                        .and_then(|object| object.get("item"))
                        .and_then(Value::as_str)
                        == Some(value)
                })
                && since.is_none_or(|value| at >= value)
                && until.is_none_or(|value| at <= value)
        })
        .collect();
    let matched = entries.len();
    if entries.len() > limit {
        entries.drain(..entries.len() - limit);
    }
    Ok(json!({"matched": matched, "returned": entries.len(), "entries": entries}))
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    _positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "audit" => Ok(Some(json!(recent(flags)?))),
        "audit-query" => Ok(Some(query(flags)?)),
        "verify-chain" => Ok(Some(chain_report(flags)?)),
        _ => Ok(None),
    }
}
