// Reading the journal back: the chain report an operator verifies with and
// the bounded recent query.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;

use super::journal::{
    acquire_append_lock, audit_path, digest_input, lines, lines_with_faults, open_for_append,
    sha256_hex, tail_lines,
};

/// Readiness check for the journal without adding health-probe noise to it.
pub fn probe() -> Result<()> {
    let path = audit_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = acquire_append_lock(&path)?;
    let file = open_for_append(&path)?;
    file.sync_data()?;
    Ok(())
}

/// What `audit verify` reports. One shape: the CLI prints it, and every
/// reader in this process reads its fields, so none re-parses the printed
/// document and stands a default in for a field it did not find.
#[derive(serde::Serialize)]
pub struct ChainReport {
    pub journal: String,
    pub entries: usize,
    pub malformed: usize,
    pub linkage_checked: usize,
    pub linkage_verified: usize,
    pub epochs: usize,
    pub digests_checked: usize,
    pub digests_verified: usize,
    pub intact: bool,
    pub broken_at: Option<String>,
    /// Each fault as `{line, at, op, fault[, detail]}`.
    pub faults: Vec<Value>,
}

/// Verify the journal's hash chain, and say which journal was verified.
///
/// The report names the selected journal: a valid default file does not prove
/// the journal used by the active vault is intact.
///
/// Two properties are checked, they fail for different reasons, and they cost
/// wildly different amounts:
///
/// - **Linkage** - each line's recorded predecessor is the line before it.
///   Two string comparisons, no hashing, so it always covers the whole
///   journal. This is the property a second writer breaks.
/// - **Digest** - the line's own fields still hash to the hash it carries.
///   This is the property a retroactive edit breaks, and it costs one
///   `shasum` process per line.
///   `--tail N` bounds it to the newest N lines.
///
/// Neither scan stops at the first fault; later valid entries and later faults
/// remain part of the report.
pub fn chain_report(flags: &HashMap<String, String>) -> Result<ChainReport> {
    let (entries, malformed) = lines_with_faults()?;
    let total = entries.len();
    // The digest scan covers the newest --tail entries, or every entry.
    let digests_from = match flags.get("tail") {
        Some(raw) => {
            let requested: std::num::NonZeroUsize = raw
                .parse()
                .context("--tail must be a whole number of at least one")?;
            Some(total.saturating_sub(requested.get()))
        }
        None => None,
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
    // The lines each check verified; their counts are the report's.
    let mut linked = Vec::new();
    let mut digested = Vec::new();
    let mut epochs = Vec::new();
    // The hash the next line must name as prev: the empty hash before the
    // genesis line, and none after a line that carries no hash.
    let mut previous_hash = Some(String::new());
    for (offset, (line, entry)) in entries.iter().enumerate() {
        let line = *line;
        let at = text(entry, "at");
        let op = text(entry, "op");
        let prev = text(entry, "prev");
        let hash = text(entry, "hash");
        let (Some(at), Some(op), Some(stored_prev), Some(stored_hash)) = (at, op, prev, hash)
        else {
            // A line missing one of these fields is neither linked nor
            // digested, so a missing prev cannot pass linkage and a missing
            // hash or op is not taken for tampering: the line is malformed and
            // says which fields.
            let missing: Vec<&str> = [("at", at), ("op", op), ("prev", prev), ("hash", hash)]
                .into_iter()
                .filter(|(_, value)| value.is_none())
                .map(|(name, _)| name)
                .collect();
            faults.push(json!({
                "line": line,
                "at": at,
                "op": op,
                "fault": "malformed",
                "detail": format!("missing or not text: {}", missing.join(", ")),
            }));
            previous_hash = hash.map(str::to_string);
            continue;
        };
        let extra = match entry.get("extra") {
            Some(extra) => extra.clone(),
            // append writes every entry with its extra; a line without one
            // hashes as the null its digest input then names.
            None => Value::Null,
        };
        let epoch_link = if op == "audit-epoch-start" {
            let prior = text(&extra, "previous_tail");
            let payload = text(&extra, "checkpoint");
            let signed = text(&extra, "signed_checkpoint");
            match (prior, payload, signed) {
                (Some(prior), Some(payload), Some(signed)) => {
                    let verification = crate::core::crypto::verify_clearsigned(signed);
                    let verified = verification
                        .as_ref()
                        .is_ok_and(|cleartext| cleartext.trim_end() == payload.trim_end());
                    let valid = stored_prev.is_empty()
                        && previous_hash.as_deref() == Some(prior)
                        && verified;
                    if valid {
                        epochs.push(line);
                    } else {
                        let detail = match verification {
                            Err(error) => Value::String(format!("checkpoint signature: {error:#}")),
                            Ok(_) => Value::Null,
                        };
                        faults.push(json!({
                            "line": line, "at": at, "op": op, "fault": "epoch", "detail": detail,
                        }));
                    }
                    valid
                }
                (prior, payload, signed) => {
                    let absent: Vec<&str> = [
                        ("previous_tail", prior),
                        ("checkpoint", payload),
                        ("signed_checkpoint", signed),
                    ]
                    .into_iter()
                    .filter(|(_, value)| value.is_none())
                    .map(|(name, _)| name)
                    .collect();
                    faults.push(json!({
                        "line": line,
                        "at": at,
                        "op": op,
                        "fault": "malformed",
                        "detail": format!("epoch start missing or not text: {}", absent.join(", ")),
                    }));
                    false
                }
            }
        } else {
            false
        };
        if previous_hash.as_deref() == Some(stored_prev) || epoch_link {
            linked.push(line);
        } else {
            faults.push(json!({"line": line, "at": at, "op": op, "fault": "linkage"}));
        }
        let in_window = match digests_from {
            Some(from) => offset >= from,
            None => true,
        };
        if in_window {
            let recomputed = sha256_hex(&digest_input(stored_prev, at, op, &extra));
            if stored_hash == recomputed {
                digested.push(line);
            } else {
                faults.push(json!({"line": line, "at": at, "op": op, "fault": "digest"}));
            }
        }
        previous_hash = Some(stored_hash.to_string());
    }
    let broken_at = faults
        .first()
        .and_then(|fault| fault.get("at"))
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(ChainReport {
        journal: audit_path().display().to_string(),
        entries: total,
        malformed: malformed.len(),
        linkage_checked: total,
        linkage_verified: linked.len(),
        epochs: epochs.len(),
        digests_checked: match digests_from {
            Some(from) => total - from,
            None => total,
        },
        digests_verified: digested.len(),
        intact: faults.is_empty(),
        broken_at,
        faults,
    })
}

/// The text field `name` of a journal line or its `extra`; `None` when it is
/// absent or not text, which the caller reports as a malformed line.
fn text<'a>(object: &'a Value, name: &str) -> Option<&'a str> {
    object.get(name).and_then(Value::as_str)
}

/// `skarbiec audit`: journal entries, oldest first, filtered by operation,
/// consumer, item and time when those are given. Without `limit` every match
/// is returned; a `limit` keeps the newest that many and must be at least
/// one. `matched` always counts every match, so a limited answer says how
/// many it left out. With no filter the limit is read from the file's tail
/// rather than by parsing the whole journal.
pub(super) fn audit(flags: &HashMap<String, String>) -> Result<Value> {
    let limit: Option<usize> = flags
        .get("limit")
        .map(|raw| {
            raw.parse::<std::num::NonZeroUsize>()
                .map(std::num::NonZeroUsize::get)
                .context("--limit must be a whole number of at least one")
        })
        .transpose()?;
    let operation = flags.get("op").map(String::as_str);
    let consumer = flags.get("consumer").map(String::as_str);
    let item = flags.get("item").map(String::as_str);
    let since = flags.get("since").map(String::as_str);
    let until = flags.get("until").map(String::as_str);
    let filtered = [operation, consumer, item, since, until]
        .iter()
        .any(Option::is_some);
    if let (false, Some(limit)) = (filtered, limit) {
        let entries = tail_lines(limit)?;
        let matched = journal_length()?;
        return Ok(json!({"matched": matched, "returned": entries.len(), "entries": entries}));
    }
    let mut entries: Vec<Value> = lines()?
        .into_iter()
        .filter(|entry| {
            let at = entry.get("at").and_then(Value::as_str);
            let extra = entry.get("extra");
            operation.is_none_or(|value| entry.get("op").and_then(Value::as_str) == Some(value))
                && consumer.is_none_or(|value| {
                    extra
                        .and_then(|object| object.get("consumer"))
                        .and_then(Value::as_str)
                        == Some(value)
                })
                // An entry names one item in `item`, or several in `items`
                // (a share or revoke by tag, a trash purge): either answers.
                && item.is_none_or(|value| {
                    extra.and_then(|object| object.get("item")).and_then(Value::as_str) == Some(value)
                        || extra
                            .and_then(|object| object.get("items"))
                            .and_then(Value::as_array)
                            .is_some_and(|items| items.iter().any(|named| named.as_str() == Some(value)))
                })
                && since.is_none_or(|value| at.is_some_and(|at| at >= value))
                && until.is_none_or(|value| at.is_some_and(|at| at <= value))
        })
        .collect();
    let matched = entries.len();
    if let Some(limit) = limit.filter(|limit| entries.len() > *limit) {
        entries.drain(..entries.len() - limit);
    }
    Ok(json!({"matched": matched, "returned": entries.len(), "entries": entries}))
}

/// How many entries the journal holds, counted by line without parsing them;
/// a journal that does not exist yet holds none.
fn journal_length() -> Result<usize> {
    let path = audit_path();
    let text = crate::core::read_present(&path, "audit journal")?;
    Ok(text
        .iter()
        .flat_map(|text| text.lines())
        .filter(|line| !line.trim().is_empty())
        .count())
}
