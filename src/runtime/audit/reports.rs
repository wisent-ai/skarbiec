// Reading the journal back: the chain report an operator verifies with and
// the bounded recent query.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;

use super::journal::{
    acquire_append_lock, audit_path, digest_input, each_entry, length, open_for_append, sha256_hex,
    tail_lines,
};
use super::segments;

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
    /// The closed segments walked before the open file.
    pub segments: usize,
    pub entries: usize,
    pub malformed: usize,
    pub linkage_checked: usize,
    pub linkage_verified: usize,
    pub epochs: usize,
    pub digests_checked: usize,
    pub digests_verified: usize,
    pub intact: bool,
    pub broken_at: Option<String>,
    /// Each fault as `{segment, line, at, op, fault[, detail]}`.
    pub faults: Vec<Value>,
}

/// A fault at `line` of `segment`.
fn fault(segment: &str, line: usize, at: Option<&str>, op: Option<&str>, kind: &str) -> Value {
    json!({"segment": segment, "line": line, "at": at, "op": op, "fault": kind})
}

/// Verify the journal's hash chain through every closed segment and the open
/// file, and say which journal was verified.
///
/// The report names the selected journal: a valid default file does not prove
/// the journal used by the active vault is intact.
///
/// Three properties are checked, they fail for different reasons, and they
/// cost different amounts:
///
/// - **Linkage** - each line's recorded predecessor is the line before it,
///   across segment boundaries too. Two string comparisons, no hashing, so it
///   always covers the whole journal. This is the property a second writer
///   breaks.
/// - **Segments** - each segment after the first opens with the
///   `audit-segment-closed` line naming the segment before it, its length in
///   bytes and its last hash, and that segment still has that length. This
///   is the property a closed segment cut, extended, removed or swapped
///   breaks.
/// - **Digest** - the line's own fields still hash to the hash it carries.
///   This is the property a retroactive edit breaks. `--tail N` bounds it to
///   the newest N lines.
///
/// The journal is read one line at a time and no scan stops at the first
/// fault; later valid entries and later faults remain part of the report.
pub fn chain_report(flags: &HashMap<String, String>) -> Result<ChainReport> {
    let journal = audit_path();
    // The digest scan covers the newest --tail lines, or every line.
    let digests_from = match flags.get("tail") {
        Some(raw) => {
            let requested: std::num::NonZeroUsize = raw
                .parse()
                .context("--tail must be a whole number of at least one")?;
            Some(length()?.saturating_sub(requested.get()))
        }
        None => None,
    };
    let files = segments::snapshot(&journal)?;
    let closed_count = files.len().saturating_sub(match files.last() {
        Some((name, _)) if *name == segments::open_name(&journal) => 1,
        _ => 0,
    });
    let mut walk = Walk {
        digests_from,
        previous_hash: Some(String::new()),
        ..Walk::default()
    };
    for (index, (segment, file)) in files.into_iter().enumerate() {
        let bytes = file
            .metadata()
            .with_context(|| format!("read the length of audit segment {segment}"))?
            .len();
        let mut first = true;
        segments::for_each_line(file, &segment, |line, text| {
            let parsed = match text {
                Ok(text) if text.trim().is_empty() => return Ok(()),
                Ok(text) => serde_json::from_str::<Value>(text).map_err(|error| error.to_string()),
                Err(error) => Err(error),
            };
            // The first line of every segment after the first must close
            // the one before it.
            let opens_segment = std::mem::replace(&mut first, false) && index > 0;
            walk.line(&segment, line, parsed, opens_segment);
            Ok(())
        })?;
        if index < closed_count {
            if first {
                // Closing moves only a journal that holds an entry, so an
                // empty closed segment was emptied or put there afterwards.
                walk.faults.push(json!({
                    "segment": segment, "line": 0, "at": null, "op": null, "fault": "segment",
                    "detail": "this closed segment holds no entry; restore it from where the closed segments are kept",
                }));
            }
            walk.closing.push((segment, bytes));
        }
    }
    let broken_at = walk
        .faults
        .first()
        .and_then(|fault| fault.get("at"))
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(ChainReport {
        journal: journal.display().to_string(),
        segments: closed_count,
        entries: walk.entries,
        malformed: walk.malformed,
        linkage_checked: walk.entries,
        linkage_verified: walk.linked,
        epochs: walk.epochs,
        digests_checked: walk.digests_checked,
        digests_verified: walk.digested,
        intact: walk.faults.is_empty(),
        broken_at,
        faults: walk.faults,
    })
}

/// The chain walk's state, one line at a time.
#[derive(Default)]
struct Walk {
    digests_from: Option<usize>,
    /// Non-blank lines read so far, the position the digest window counts.
    position: usize,
    /// The hash the next line must name as prev: the empty hash before the
    /// genesis line, and none after a line that carries no hash.
    previous_hash: Option<String>,
    /// Every closed segment read, with its length, in order; the line that
    /// opens the next segment must name the last of them.
    closing: Vec<(String, u64)>,
    entries: usize,
    malformed: usize,
    linked: usize,
    epochs: usize,
    digests_checked: usize,
    digested: usize,
    faults: Vec<Value>,
}

impl Walk {
    fn line(
        &mut self,
        segment: &str,
        line: usize,
        parsed: std::result::Result<Value, String>,
        opens_segment: bool,
    ) {
        let position = self.position;
        self.position += 1;
        let entry = match parsed {
            Ok(entry) => entry,
            Err(error) => {
                self.malformed += 1;
                let mut found = fault(segment, line, None, None, "malformed");
                found["detail"] = json!(error);
                self.faults.push(found);
                if opens_segment {
                    self.segment_unnamed(segment, line, None, None);
                }
                return;
            }
        };
        self.entries += 1;
        let at = text(&entry, "at");
        let op = text(&entry, "op");
        let prev = text(&entry, "prev");
        let hash = text(&entry, "hash");
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
            let mut found = fault(segment, line, at, op, "malformed");
            found["detail"] = json!(format!("missing or not text: {}", missing.join(", ")));
            self.faults.push(found);
            if opens_segment {
                self.segment_unnamed(segment, line, at, op);
            }
            self.previous_hash = hash.map(str::to_string);
            return;
        };
        let extra = match entry.get("extra") {
            Some(extra) => extra.clone(),
            // append writes every entry with its extra; a line without one
            // hashes as the null its digest input then names.
            None => Value::Null,
        };
        self.segment_link(segment, line, at, op, &extra, opens_segment);
        let epoch_link =
            op == "audit-epoch-start" && self.epoch(segment, line, at, op, stored_prev, &extra);
        if self.previous_hash.as_deref() == Some(stored_prev) || epoch_link {
            self.linked += 1;
        } else {
            self.faults
                .push(fault(segment, line, Some(at), Some(op), "linkage"));
        }
        let in_window = match self.digests_from {
            Some(from) => position >= from,
            None => true,
        };
        if in_window {
            self.digests_checked += 1;
            let recomputed = sha256_hex(&digest_input(stored_prev, at, op, &extra));
            if stored_hash == recomputed {
                self.digested += 1;
            } else {
                self.faults
                    .push(fault(segment, line, Some(at), Some(op), "digest"));
            }
        }
        self.previous_hash = Some(stored_hash.to_string());
    }

    /// The first line of a segment after a closed one must close it; an
    /// `audit-segment-closed` line anywhere else closes nothing.
    fn segment_link(
        &mut self,
        segment: &str,
        line: usize,
        at: &str,
        op: &str,
        extra: &Value,
        opens_segment: bool,
    ) {
        if !opens_segment {
            if op == segments::CLOSED_OP {
                let mut found = fault(segment, line, Some(at), Some(op), "segment");
                found["detail"] =
                    json!("this line closes a segment but is not the first line after one");
                self.faults.push(found);
            }
            return;
        }
        if op != segments::CLOSED_OP {
            self.segment_unnamed(segment, line, Some(at), Some(op));
            return;
        }
        let Some((closed, bytes)) = self.closing.last().cloned() else {
            return;
        };
        let mut wrong = Vec::new();
        if text(extra, "segment") != Some(closed.as_str()) {
            wrong.push(format!(
                "it names segment {} where the segment before it is {closed}",
                extra["segment"]
            ));
        }
        if extra.get("bytes").and_then(Value::as_u64) != Some(bytes) {
            wrong.push(format!(
                "it records {} bytes where {closed} now holds {bytes}, so the closed segment \
                 was cut, extended or replaced",
                extra["bytes"]
            ));
        }
        if text(extra, "last_hash") != self.previous_hash.as_deref() {
            wrong.push(format!(
                "it records last hash {} where {closed} ends with {}",
                extra["last_hash"],
                json!(self.previous_hash)
            ));
        }
        if !wrong.is_empty() {
            let mut found = fault(segment, line, Some(at), Some(op), "segment");
            found["detail"] = json!(wrong.join("; "));
            self.faults.push(found);
        }
    }

    /// A segment whose first line is not the one closing the segment before.
    fn segment_unnamed(&mut self, segment: &str, line: usize, at: Option<&str>, op: Option<&str>) {
        let closed = match self.closing.last() {
            Some((closed, _)) => closed.clone(),
            None => "the segment before".to_string(),
        };
        let mut found = fault(segment, line, at, op, "segment");
        found["detail"] = json!(format!(
            "the first line of this segment is not the {} line naming {closed}",
            segments::CLOSED_OP
        ));
        self.faults.push(found);
    }

    /// Whether an epoch start validly restarts the chain: an empty prev, the
    /// previous tail it names, and a checkpoint the owner signed.
    fn epoch(
        &mut self,
        segment: &str,
        line: usize,
        at: &str,
        op: &str,
        stored_prev: &str,
        extra: &Value,
    ) -> bool {
        let prior = text(extra, "previous_tail");
        let payload = text(extra, "checkpoint");
        let signed = text(extra, "signed_checkpoint");
        let (Some(prior), Some(payload), Some(signed)) = (prior, payload, signed) else {
            let absent: Vec<&str> = [
                ("previous_tail", prior),
                ("checkpoint", payload),
                ("signed_checkpoint", signed),
            ]
            .into_iter()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name)
            .collect();
            let mut found = fault(segment, line, Some(at), Some(op), "malformed");
            found["detail"] = json!(format!(
                "epoch start missing or not text: {}",
                absent.join(", ")
            ));
            self.faults.push(found);
            return false;
        };
        let verification = crate::core::crypto::verify_clearsigned(signed);
        let verified = verification
            .as_ref()
            .is_ok_and(|cleartext| cleartext.trim_end() == payload.trim_end());
        let valid =
            stored_prev.is_empty() && self.previous_hash.as_deref() == Some(prior) && verified;
        if valid {
            self.epochs += 1;
        } else {
            let mut found = fault(segment, line, Some(at), Some(op), "epoch");
            found["detail"] = match verification {
                Err(error) => Value::String(format!("checkpoint signature: {error:#}")),
                Ok(_) => Value::Null,
            };
            self.faults.push(found);
        }
        valid
    }
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
        let matched = length()?;
        return Ok(json!({"matched": matched, "returned": entries.len(), "entries": entries}));
    }
    let keeps = |entry: &Value| {
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
    };
    // Read one line at a time across every segment; with a limit only the
    // newest that many matches are held.
    let mut entries = std::collections::VecDeque::new();
    let mut matched = 0;
    each_entry(|segment, line, parsed| {
        let entry = parsed.map_err(|error| {
            anyhow::anyhow!(
                "audit journal {} holds a line that is not an entry, in segment {segment} at \
                 line {line}: {error}; `skarbiec audit verify` reports every such line",
                audit_path().display()
            )
        })?;
        if keeps(&entry) {
            matched += 1;
            entries.push_back(entry);
            if limit.is_some_and(|limit| entries.len() > limit) {
                entries.pop_front();
            }
        }
        Ok(())
    })?;
    Ok(json!({"matched": matched, "returned": entries.len(), "entries": entries}))
}
