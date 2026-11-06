// The journal file itself: where it is, how a line is hashed onto the one
// before it, the lock that keeps two writers from sharing a predecessor, and
// the closed segments (`segments`) the chain runs through before the open file.

use anyhow::{Context, Result};
use fs2::FileExt;
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::segments;

/// The audit journal: `SKARBIEC_AUDIT_FILE`, else under the user's home as
/// `crate::core::home_dir` resolves it, never under the directory the process
/// started in. This is the open file; closed segments sit in `<journal>.d/`.
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

/// Read and write for the owner alone, the mode every journal file is
/// created with.
fn owner_only_file() -> u32 {
    crate::core::mode::OWNER_READ_WRITE
}

/// Read, write and search for the owner alone, the mode of the journal's
/// directory.
fn owner_only_directory() -> u32 {
    crate::core::mode::OWNER_ALL
}

/// Call `each` for every non-blank line of every segment, oldest first,
/// with the segment it was read from (a closed segment's file name, or the
/// open file's), its line number there as an editor counts it, and the
/// entry or why the line is not one. Lines are read one at a time, so a
/// journal of any size costs memory for one line.
pub(super) fn each_entry(
    mut each: impl FnMut(&str, usize, std::result::Result<Value, String>) -> Result<()>,
) -> Result<()> {
    for (segment, file) in segments::snapshot(&audit_path())? {
        segments::for_each_line(file, &segment, |line, text| match text {
            Ok(text) if text.trim().is_empty() => Ok(()),
            Ok(text) => each(
                &segment,
                line,
                serde_json::from_str(text).map_err(|error| error.to_string()),
            ),
            Err(error) => each(&segment, line, Err(error)),
        })?;
    }
    Ok(())
}

// The material each line's hash covers: previous hash + the line's own fields.
pub(super) fn digest_input(prev: &str, at: &str, op: &str, extra: &Value) -> String {
    format!("{prev}|{at}|{op}|{extra}")
}

/// The SHA-256 of `input`, as the lowercase hex the journal chains with.
pub(super) fn sha256_hex(input: &str) -> String {
    crate::core::crypto::sha256_hex_bytes(input.as_bytes())
}

/// A file's complete lines in a window reaching back `window` bytes from its
/// end, and whether that window reaches the start of the file.
fn tail_window(file: &mut File, length: u64, window: u64) -> Result<(Vec<String>, bool)> {
    let from_start = window >= length;
    file.seek(std::io::SeekFrom::Start(length.saturating_sub(window)))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    // A window that opens mid-file may cut its first line, even inside a
    // character, so everything before its first line break is left out
    // before the rest is decoded.
    let complete: &[u8] = match (from_start, bytes.iter().position(|byte| *byte == b'\n')) {
        (true, _) => &bytes,
        (false, Some(first_break)) => &bytes[first_break..],
        (false, None) => &[],
    };
    let text =
        std::str::from_utf8(complete).context("audit journal holds text that is not UTF-8")?;
    let lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    Ok((lines, from_start))
}

/// The first window a tail read takes: the file system's preferred I/O block
/// for the journal. Each wider window doubles it.
fn first_window(metadata: &fs::Metadata) -> Result<u64> {
    Ok(std::num::NonZeroU64::new(metadata.blksize())
        .context("the file system reports no I/O block size for the audit journal")?
        .get())
}

/// The last `limit` complete lines of `file`, read in widening windows from
/// its end, fewer when the file holds fewer.
fn tail_of(mut file: File, limit: usize) -> Result<Vec<String>> {
    let metadata = file.metadata()?;
    let length = metadata.len();
    let mut window = first_window(&metadata)?;
    loop {
        let (lines, from_start) = tail_window(&mut file, length, window)?;
        if lines.len() >= limit || from_start {
            let excess = lines.len().saturating_sub(limit);
            return Ok(lines[excess..].to_vec());
        }
        // Each wider window reads as much again as the last one did.
        window = window.saturating_add(window);
    }
}

/// The hash of the last complete line of a journal file `path` names, or
/// none when it holds no line. The last entry must parse and carry its hash,
/// because chaining onto an older hash or restarting the chain would fork
/// the tamper-evident journal.
pub(super) fn last_hash_of(file: File, path: &Path) -> Result<Option<String>> {
    let Some(last) = tail_of(file, 1)?.pop() else {
        return Ok(None);
    };
    let entry: Value = serde_json::from_str(&last).with_context(|| {
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
    Ok(Some(hash.to_string()))
}

/// The hash the next line chains onto: the open file's last, else the last
/// closed segment's, else the empty hash (the chain starts here).
pub(super) fn tail_hash() -> Result<String> {
    let path = audit_path();
    if let Some(hash) = segments::last_hash(&path)? {
        return Ok(hash);
    }
    match segments::closed(&path)?.last() {
        Some(segment) => Ok(segments::measured(segment)?.1),
        None => Ok(String::new()),
    }
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

/// Parse only the journal's final `limit` entries, walking backwards from
/// the open file through the closed segments in widening windows, so the
/// cost follows the size of the answer instead of the size of the journal.
pub(super) fn tail_lines(limit: usize) -> Result<Vec<Value>> {
    let mut files = segments::snapshot(&audit_path())?;
    let mut lines: Vec<String> = Vec::new();
    while lines.len() < limit {
        let Some((_, file)) = files.pop() else {
            break;
        };
        let mut older = tail_of(file, limit - lines.len())?;
        older.append(&mut lines);
        lines = older;
    }
    lines
        .iter()
        .map(|line| serde_json::from_str(line).context("audit line is not JSON"))
        .collect()
}

/// How many entries the journal holds across every segment, counted by line
/// without parsing them; a journal that does not exist yet holds none.
pub(super) fn length() -> Result<usize> {
    let mut count = 0;
    for (segment, file) in segments::snapshot(&audit_path())? {
        segments::for_each_line(file, &segment, |_, text| {
            if text.is_err() || text.is_ok_and(|text| !text.trim().is_empty()) {
                count += 1;
            }
            Ok(())
        })?;
    }
    Ok(count)
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

/// Write one entry chained onto `prev` at the end of the open file and make
/// it durable; answers its hash.
fn write_entry(path: &Path, prev: &str, op: &str, extra: &Value) -> Result<String> {
    let at = now_iso();
    let hash = sha256_hex(&digest_input(prev, &at, op, extra));
    let entry = json!({"at": at, "op": op, "extra": extra, "prev": prev, "hash": hash});
    // A journal that cannot be examined is refused, not taken for a fresh one
    // whose directory entry then goes unsynced.
    let fresh = !crate::core::is_present(path, "the audit journal")?;
    let mut file = open_for_append(path)?;
    writeln!(file, "{entry}")?;
    file.sync_data()?;
    if fresh {
        File::open(path.parent().context("audit path has no parent")?)?.sync_all()?;
    }
    Ok(hash)
}

/// Close the open file as the next segment and write the line that names
/// it; the caller holds the append lock. `None` when there was nothing to
/// close.
fn close_segment(path: &Path, why: &str) -> Result<Option<Value>> {
    let Some(mut closed) = segments::close(path)? else {
        return Ok(None);
    };
    closed["why"] = json!(why);
    let last = closed["last_hash"]
        .as_str()
        .context("a closed audit segment records no last hash")?
        .to_string();
    let hash = write_entry(path, &last, segments::CLOSED_OP, &closed)?;
    closed["hash"] = json!(hash);
    Ok(Some(closed))
}

/// `skarbiec audit rotate`: close the open file now rather than at the next
/// UTC day. An open file with no entry, or none beyond the line that closed
/// the segment before it, has nothing to close and says so.
pub(super) fn rotate() -> Result<Value> {
    let path = audit_path();
    let _lock = acquire_append_lock(&path)?;
    finish_interrupted_close(&path)?;
    if let Some(segment) = segments::holds_only_closing(&path)? {
        return Ok(json!({
            "rotated": false,
            "reason": format!(
                "audit journal {} holds no entry beyond the line that closed {segment}, so there is no segment to close",
                path.display()
            ),
        }));
    }
    match close_segment(&path, "audit rotate closed it")? {
        Some(closed) => Ok(json!({"rotated": true, "closed": closed})),
        None => Ok(json!({
            "rotated": false,
            "reason": format!("audit journal {} holds no entry, so there is no segment to close", path.display()),
        })),
    }
}

/// When the open file holds no entry but a closed segment exists, a close
/// stopped after its rename, before the line naming the segment was
/// written; that line is written now, so the chain names every segment.
fn finish_interrupted_close(path: &Path) -> Result<()> {
    if segments::last_hash(path)?.is_some() {
        return Ok(());
    }
    if let Some(segment) = segments::closed(path)?.last() {
        let (bytes, last) = segments::measured(segment)?;
        let extra = json!({
            "segment": segments::segment_name(segment),
            "bytes": bytes,
            "last_hash": last,
            "why": "the close of this segment stopped before its line was written",
        });
        write_entry(path, &last, segments::CLOSED_OP, &extra)?;
    }
    Ok(())
}

/// Before an append: finish a close that stopped half way, and close the
/// open file when it began on an earlier UTC day. Runs under the append lock.
pub(super) fn rotate_if_due(path: &Path) -> Result<()> {
    finish_interrupted_close(path)?;
    let today = OffsetDateTime::now_utc().date().to_string();
    if segments::began_before(path, &today)? {
        close_segment(path, "the open segment began on an earlier UTC day")?;
    }
    Ok(())
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
    rotate_if_due(&path)?;
    let prev = tail_hash()?;
    write_entry(&path, &prev, op, extra)?;
    Ok(())
}
