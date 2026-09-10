// Reading the journal back: the chain report an operator verifies with, the
// bounded recent query, and the epoch a new chain starts from.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use super::journal::{
    acquire_append_lock, audit_path, digest_input, lines, lines_with_faults, now_iso, sha256_hex,
    tail_hash, tail_lines,
};

/// Readiness check for the journal without adding health-probe noise to it.
pub fn probe() -> Result<()> {
    let path = audit_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = acquire_append_lock(&path)?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.sync_data()?;
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
    let (entries, malformed) = lines_with_faults()?;
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
    let mut faults: Vec<Value> = malformed
        .iter()
        .map(|fault| {
            json!({
                "line": fault.get("line"),
                "at": Value::Null,
                "op": Value::Null,
                "fault": "malformed",
                "detail": fault.get("error"),
            })
        })
        .collect();
    let mut linked = usize::MIN;
    let mut digested = usize::MIN;
    let mut epochs = usize::MIN;
    let mut previous_hash = String::new();
    for (offset, entry) in entries.iter().enumerate() {
        let at = entry.get("at").and_then(Value::as_str).unwrap_or("");
        let op = entry.get("op").and_then(Value::as_str).unwrap_or("");
        let stored_prev = entry.get("prev").and_then(Value::as_str).unwrap_or("");
        let stored_hash = entry.get("hash").and_then(Value::as_str).unwrap_or("");
        let extra = entry.get("extra").cloned().unwrap_or(Value::Null);
        let line = offset.saturating_add(one);
        let epoch_link = if op == "audit-epoch-start" {
            let prior = extra
                .get("previous_tail")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let payload = extra
                .get("checkpoint")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let signed = extra
                .get("signed_checkpoint")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let verified = crate::core::crypto::verify_clearsigned(signed)
                .map(|cleartext| cleartext.trim_end() == payload.trim_end())
                .unwrap_or(false);
            let valid = stored_prev.is_empty() && prior == previous_hash && verified;
            if valid {
                epochs = epochs.saturating_add(one);
            } else {
                faults.push(json!({"line": line, "at": at, "op": op, "fault": "epoch"}));
            }
            valid
        } else {
            false
        };
        if stored_prev == previous_hash || epoch_link {
            linked = linked.saturating_add(one);
        } else {
            faults.push(json!({"line": line, "at": at, "op": op, "fault": "linkage"}));
        }
        if offset >= digests_from {
            let recomputed = sha256_hex(&digest_input(stored_prev, at, op, &extra));
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
        "malformed": malformed.len(),
        "linkage_checked": total,
        "linkage_verified": linked,
        "epochs": epochs,
        "digests_checked": total.saturating_sub(digests_from),
        "digests_verified": digested,
        "intact": faults.is_empty(),
        "broken_at": broken_at,
        "faults": faults,
    }))
}

/// The journal, oldest first. `--limit N` returns only the final N, read from
/// the file's tail rather than parsed in full.
pub(super) fn recent(flags: &HashMap<String, String>) -> Result<Vec<Value>> {
    let Some(raw) = flags.get("limit") else {
        return lines();
    };
    let limit: usize = raw.parse().context("--limit must be a whole number")?;
    if limit == usize::MIN {
        anyhow::bail!("--limit must be at least one");
    }
    tail_lines(limit)
}

pub(super) fn query(flags: &HashMap<String, String>) -> Result<Value> {
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

pub(super) fn start_epoch(flags: &HashMap<String, String>) -> Result<Value> {
    let reason = flags
        .get("reason")
        .map(String::as_str)
        .filter(|reason| !reason.trim().is_empty())
        .context("--reason is required")?;
    let report = chain_report(&HashMap::new())?;
    if report.get("intact").and_then(Value::as_bool) == Some(true) {
        anyhow::bail!("audit journal is intact; refusing to create an unnecessary epoch");
    }
    let path = audit_path();
    let previous_tail = tail_hash()?;
    let _lock = acquire_append_lock(&path)?;
    if tail_hash()? != previous_tail {
        anyhow::bail!("audit journal changed while preparing checkpoint; retry");
    }
    let vault = crate::core::vault::Vault::open(crate::core::vault_path())?;
    let owner = vault
        .doc()
        .get("owner")
        .and_then(Value::as_str)
        .context("vault owner is missing")?;
    let signer = vault
        .doc()
        .get("recipients")
        .and_then(Value::as_object)
        .and_then(|recipients| recipients.get(owner))
        .and_then(|recipient| recipient.get("fingerprint"))
        .and_then(Value::as_str)
        .context("vault owner fingerprint is missing")?;
    let at = now_iso();
    let checkpoint = serde_json::to_string(&json!({
        "at": at,
        "reason": reason,
        "previous_tail": previous_tail,
        "broken_at": report.get("broken_at").cloned().unwrap_or(Value::Null),
        "faults": report
            .get("faults")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or_default(),
    }))?;
    let signed_checkpoint = crate::core::crypto::clearsign(signer, &checkpoint)?;
    let extra = json!({
        "reason": reason,
        "previous_tail": previous_tail,
        "signer": signer,
        "checkpoint": checkpoint,
        "signed_checkpoint": signed_checkpoint,
    });
    let prev = String::new();
    let hash = sha256_hex(&digest_input(&prev, &at, "audit-epoch-start", &extra));
    let entry = json!({
        "at": at,
        "op": "audit-epoch-start",
        "extra": extra,
        "prev": prev,
        "hash": hash,
    });
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;
    writeln!(file, "{entry}")?;
    file.sync_data()?;
    Ok(json!({
        "started": true,
        "signer": signer,
        "previous_tail": previous_tail,
        "hash": hash,
    }))
}
