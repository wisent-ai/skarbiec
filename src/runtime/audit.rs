// Tamper-evident audit journal. Each line records at/op/extra plus the hash of
// the previous line, forming a chain: any retroactive edit breaks every hash
// after it, which `verify-chain` detects. Values are never journalled — only
// operation names and non-sensitive identifiers.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read as _, Seek as _, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use crate::core::crypto;

// Appends are serialized process-wide: the hash chain is read-modify-write,
// so concurrent handlers (the HTTP listener is thread-per-connection) must
// never interleave two appends. High-frequency read paths enqueue entries on
// a channel that one worker thread journals; mutating operations call
// `append_sync` so their evidence is durable before the response returns.
static TAIL: OnceLock<Mutex<Option<String>>> = OnceLock::new();
static QUEUE: OnceLock<std::sync::mpsc::Sender<(String, Value)>> = OnceLock::new();

fn tail_lock() -> &'static Mutex<Option<String>> {
    TAIL.get_or_init(|| Mutex::new(None))
}

fn queue() -> &'static std::sync::mpsc::Sender<(String, Value)> {
    QUEUE.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<(String, Value)>();
        std::thread::spawn(move || {
            while let Ok((op, extra)) = rx.recv() {
                if let Err(error) = append_sync(&op, &extra) {
                    eprintln!("audit append failed: {error}");
                }
            }
        });
        tx
    })
}

fn audit_path() -> PathBuf {
    if let Ok(p) = std::env::var("SKARBIEC_AUDIT_FILE") {
        return PathBuf::from(p);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".stado/skarbiec.audit.jsonl")
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

/// Queue one entry for the background journal worker. Read paths use this so
/// the hash-chain serialization (two subprocess spawns per line) never lands
/// on the consumer's response latency. Falls back to a synchronous append
/// when the worker is gone, so evidence is never silently dropped.
pub fn append(op: &str, extra: &Value) -> Result<()> {
    match queue().send((op.to_string(), extra.clone())) {
        Ok(()) => Ok(()),
        Err(std::sync::mpsc::SendError((op, extra))) => append_sync(&op, &extra),
    }
}

/// Append one hash-chained entry inline. `prev` is the previous line's hash
/// (empty for the genesis line). Never records any stored value.
pub fn append_sync(op: &str, extra: &Value) -> Result<()> {
    let mut tail = tail_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = match tail.as_ref() {
        Some(cached) => cached.clone(),
        None => tail_hash()?,
    };
    let at = now_iso();
    let hash = crypto::sha256_hex(&digest_input(&prev, &at, op, extra))?;
    let entry = json!({"at": at, "op": op, "extra": extra, "prev": prev, "hash": hash});
    let path = audit_path();
    let fresh = !path.exists();
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{entry}")?;
    if fresh {
        Command::new("chmod").arg("600").arg(&path).status().ok();
    }
    *tail = Some(hash);
    Ok(())
}

fn verify_chain() -> Result<Value> {
    let entries = lines()?;
    let mut prev = String::new();
    let mut broken_at: Option<String> = None;
    for entry in &entries {
        let at = entry.get("at").and_then(Value::as_str).unwrap_or("");
        let op = entry.get("op").and_then(Value::as_str).unwrap_or("");
        let extra = entry.get("extra").cloned().unwrap_or(Value::Null);
        let stored_prev = entry.get("prev").and_then(Value::as_str).unwrap_or("");
        let stored_hash = entry.get("hash").and_then(Value::as_str).unwrap_or("");
        let recomputed = crypto::sha256_hex(&digest_input(&prev, at, op, &extra))?;
        if stored_prev != prev || stored_hash != recomputed {
            broken_at = Some(at.to_string());
            break;
        }
        prev = stored_hash.to_string();
    }
    Ok(json!({
        "entries": entries.len(),
        "intact": broken_at.is_none(),
        "broken_at": broken_at,
    }))
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
        "audit" => Ok(Some(json!(lines()?))),
        "audit-query" => Ok(Some(query(flags)?)),
        "verify-chain" => Ok(Some(verify_chain()?)),
        _ => Ok(None),
    }
}
