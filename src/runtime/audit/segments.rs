//! The journal in segments: the open file at the journal's path, which every
//! append writes to, and the closed segments before it in `<journal>.d/`,
//! numbered from `000000.jsonl` in the order they were closed. One hash
//! chain runs through all of them: the first line written after a segment
//! closes is `audit-segment-closed`, whose `prev` is that segment's last hash
//! and whose `extra` names the segment, its length in bytes and that hash, so
//! a closed segment that was cut, extended or swapped no longer matches the
//! line that closed it.
//!
//! A segment closes at the first append of a new UTC day, or when
//! `skarbiec audit rotate` closes it. Closing renames the open file into
//! `<journal>.d/` and makes it read-only; nothing is rewritten, so a journal
//! written before segments existed becomes `000000.jsonl` as it is.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The operation of the line that opens a segment after one closed.
pub(super) const CLOSED_OP: &str = "audit-segment-closed";
/// Digits in a segment's number.
const DIGITS: usize = 6;
/// Owner read only: a closed segment is never written again.
const CLOSED_MODE: u32 = 0o400;

/// The directory the closed segments of `journal` are kept in.
pub(super) fn directory(journal: &Path) -> PathBuf {
    let mut name = journal.as_os_str().to_os_string();
    name.push(".d");
    PathBuf::from(name)
}

/// The closed segments of `journal`, oldest first: each file of the segment
/// directory named by a number of six digits and `.jsonl`, numbered from
/// zero without a gap. A directory that does not exist holds none; any other
/// file in it, or a missing number, is refused, since the chain would be
/// read without part of it.
pub(super) fn closed(journal: &Path) -> Result<Vec<PathBuf>> {
    let directory = directory(journal);
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "list the closed audit segments in {}; give this user read and search \
                     permission on it",
                    directory.display()
                )
            })
        }
    };
    let mut numbered = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| {
            format!("list the closed audit segments in {}", directory.display())
        })?;
        let name = entry.file_name();
        let number = name
            .to_str()
            .and_then(|name| name.strip_suffix(".jsonl"))
            .filter(|digits| digits.len() == DIGITS && digits.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|digits| digits.parse::<usize>().ok());
        let Some(number) = number else {
            bail!(
                "{} holds {}, which is not a closed audit segment (NNNNNN.jsonl), so the \
                 journal cannot be read with everything in it accounted for; move that file \
                 out of the directory",
                directory.display(),
                entry.path().display()
            );
        };
        numbered.push((number, entry.path()));
    }
    numbered.sort();
    for (expected, (number, path)) in numbered.iter().enumerate() {
        if *number != expected {
            bail!(
                "closed audit segment {expected:0width$}.jsonl is missing from {} (the next \
                 present is {}), so the chain cannot be followed through it; restore it from \
                 where the closed segments are kept",
                directory.display(),
                path.display(),
                width = DIGITS
            );
        }
    }
    Ok(numbered.into_iter().map(|(_, path)| path).collect())
}

/// Every file of the journal, oldest first, opened: the closed segments,
/// then the open file. Reading takes no lock: when a segment closes between
/// listing the closed ones and opening the open file, the list is taken
/// again, so each line is read once, from the file it was in.
pub(super) fn snapshot(journal: &Path) -> Result<Vec<(String, File)>> {
    loop {
        let listed = closed(journal)?;
        let mut files = Vec::new();
        for path in &listed {
            let file = File::open(path).with_context(|| {
                format!(
                    "open the closed audit segment {}; give this user read permission on it",
                    path.display()
                )
            })?;
            files.push((segment_name(path), file));
        }
        match File::open(journal) {
            Ok(file) => files.push((open_name(journal), file)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "open audit journal {}; give this user read permission on it",
                        journal.display()
                    )
                })
            }
        }
        if closed(journal)?.len() == listed.len() {
            return Ok(files);
        }
    }
}

/// How a closed segment is named in a report: its file name.
pub(super) fn segment_name(path: &Path) -> String {
    match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => name.to_string(),
        None => path.display().to_string(),
    }
}

/// How the open file is named in a report.
pub(super) fn open_name(journal: &Path) -> String {
    format!("{} (open)", segment_name(journal))
}

/// How many leading lines the age check reads for the first one stating its
/// time before it leaves the open file open.
const AGE_LINES: usize = 64;

/// Whether the open file began on an earlier UTC day than `today`
/// (`YYYY-MM-DD`): the age a segment closes at. It is read from the first
/// entry stating its time among the file's first lines. A line that is not
/// one does not stop an append: `audit verify` and `doctor` report it, and
/// the open file stays open until such an entry is found or `audit rotate`
/// closes it.
pub(super) fn began_before(journal: &Path, today: &str) -> Result<bool> {
    let file = match File::open(journal) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("open audit journal {}", journal.display()))
        }
    };
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    for _ in 0..AGE_LINES {
        line.clear();
        let read = reader
            .read_until(b'\n', &mut line)
            .with_context(|| format!("read audit journal {}", journal.display()))?;
        if read == 0 {
            break;
        }
        let at = serde_json::from_slice::<Value>(&line)
            .ok()
            .and_then(|entry| entry.get("at").and_then(Value::as_str).map(str::to_string));
        if let Some(at) = at {
            return Ok(at.get(..10).is_some_and(|day| day < today));
        }
    }
    Ok(false)
}

/// The last hash in the journal file at `path`, read from its end; `None`
/// when it is absent or holds no line.
pub(super) fn last_hash(path: &Path) -> Result<Option<String>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("open audit journal {}", path.display()))
        }
    };
    super::journal::last_hash_of(file, path)
}

/// The segment the open file's only entry closes, when that line is all it
/// holds; `None` when it holds anything else or nothing.
pub(super) fn holds_only_closing(journal: &Path) -> Result<Option<String>> {
    let file = match File::open(journal) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("open audit journal {}", journal.display()))
        }
    };
    // Two entries are enough to tell, so no more of the file is read.
    let mut reader = BufReader::new(file);
    let mut entries = Vec::new();
    let mut line = Vec::new();
    while entries.len() < 2 {
        line.clear();
        let read = reader
            .read_until(b'\n', &mut line)
            .with_context(|| format!("read audit journal {}", journal.display()))?;
        if read == 0 {
            break;
        }
        if !line.trim_ascii().is_empty() {
            entries.push(serde_json::from_slice::<Value>(&line).ok());
        }
    }
    match entries.as_slice() {
        [Some(only)] if only.get("op").and_then(Value::as_str) == Some(CLOSED_OP) => Ok(only
            .pointer("/extra/segment")
            .and_then(Value::as_str)
            .map(str::to_string)),
        _ => Ok(None),
    }
}

/// A closed segment's byte length and last hash as they are now, to compare
/// with the line that closed it.
pub(super) fn measured(path: &Path) -> Result<(u64, String)> {
    let bytes = fs::metadata(path)
        .with_context(|| format!("read the length of {}", path.display()))?
        .len();
    let last = match last_hash(path)? {
        Some(hash) => hash,
        None => String::new(),
    };
    Ok((bytes, last))
}

/// Sync a directory, so a rename in it survives a crash.
fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .and_then(|handle| handle.sync_all())
        .with_context(|| {
            format!(
                "sync {} after closing an audit segment",
                directory.display()
            )
        })
}

/// Move the open file into the segment directory as the next closed segment
/// and make it read-only; the caller holds the append lock and writes the
/// line that names it. Answers the segment's name, bytes and last hash, or
/// `None` when the open file holds no entry.
pub(super) fn close(journal: &Path) -> Result<Option<Value>> {
    let Some(last) = last_hash(journal)? else {
        return Ok(None);
    };
    let bytes = fs::metadata(journal)
        .with_context(|| format!("read the length of audit journal {}", journal.display()))?
        .len();
    let directory = directory(journal);
    fs::DirBuilder::new()
        .recursive(true)
        .create(&directory)
        .with_context(|| {
            format!(
                "create the audit segment directory {}; give this user write permission on \
                 the journal's directory",
                directory.display()
            )
        })?;
    fs::set_permissions(
        &directory,
        fs::Permissions::from_mode(crate::core::mode::OWNER_ALL),
    )
    .with_context(|| {
        format!(
            "protect the audit segment directory {}",
            directory.display()
        )
    })?;
    let number = closed(journal)?.len();
    let target = directory.join(format!("{number:0width$}.jsonl", width = DIGITS));
    if crate::core::is_present(&target, "the next closed audit segment")? {
        bail!(
            "closed audit segment {} already exists, so the open journal is not moved over \
             it; move it out of {} and close the segment again",
            target.display(),
            directory.display()
        );
    }
    fs::rename(journal, &target).with_context(|| {
        format!(
            "move the open audit journal {} to {} to close it; both must be on one file system",
            journal.display(),
            target.display()
        )
    })?;
    fs::set_permissions(&target, fs::Permissions::from_mode(CLOSED_MODE)).with_context(|| {
        format!(
            "make the closed audit segment {} read-only",
            target.display()
        )
    })?;
    sync_directory(&directory)?;
    if let Some(parent) = journal
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        sync_directory(parent)?;
    }
    Ok(Some(json!({
        "segment": segment_name(&target),
        "bytes": bytes,
        "last_hash": last,
    })))
}

/// Read every line of `file`, calling `each` with its 1-based number and its
/// text without the line break. A journal line is read as UTF-8; one that is
/// not is passed on as a fault rather than ending the read.
pub(super) fn for_each_line(
    file: File,
    name: &str,
    mut each: impl FnMut(usize, Result<&str, String>) -> Result<()>,
) -> Result<()> {
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut number = 0;
    loop {
        line.clear();
        let read = reader
            .read_until(b'\n', &mut line)
            .with_context(|| format!("read audit journal segment {name}"))?;
        if read == 0 {
            return Ok(());
        }
        number += 1;
        let text = std::str::from_utf8(&line)
            .map(|text| text.trim_end_matches(['\n', '\r']))
            .map_err(|error| format!("not UTF-8: {error}"));
        each(number, text)?;
    }
}
