// `skarbiec scan <path>... --fields <field,...> [--min-length <N>] [--refuse]`: find the
// files on this machine that hold a vault value in plain text — a .env left
// behind after env import, a config file, a shell history, a note — so each
// copy can be deleted or the value rotated. Every live item's named fields
// are opened and compared, byte for byte, with every regular file under the
// paths; the answer names the file, the line, the item and the field, never
// the value. Symbolic links are not followed, so a scan stays where it was
// pointed; a file or directory that cannot be read is named with its error.
// With --refuse a copy found is an error naming every one, so a git hook or
// a CI step stops on it. With --history the one path is a git repository,
// and its commits on every branch are read instead of its files (`history`).

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use crate::cli::args::{flag_set, OrUsage, Usage};
use crate::core::{schema, vault::Vault, vault_path};

const USAGE: &str = "usage: scan <path>... --fields <field,...> [--min-length <N>] [--refuse] | scan <repo> --history --fields <field,...> [--min-length <N>]";

/// One value compared: the item and field it is kept in, and its bytes.
struct Held {
    item: String,
    field: String,
    value: String,
}

/// One plain-text copy: the file, the line it starts on, and what it holds.
struct PlainCopy {
    file: String,
    line: usize,
    item: String,
    field: String,
}

/// What a walk saw: each copy found and each path it could not read.
#[derive(Default)]
struct Walk {
    files_read: Vec<String>,
    found: Vec<PlainCopy>,
    unreadable: Vec<Value>,
}

mod history;

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "scan" {
        return Ok(None);
    }
    if flag_set(flags, "history") {
        return history::run(flags, positionals).map(Some);
    }
    if positionals.is_empty() {
        return Err(Usage(USAGE.to_string()).into());
    }
    let (fields, minimum) = requested(flags, USAGE)?;
    let (held, unreadable_items, below_minimum) = values(&fields, minimum)?;
    let here = std::env::current_dir().context("read the working directory")?;
    let mut walk = Walk::default();
    for path in positionals {
        visit(&here.join(path), &held, &mut walk);
    }
    crate::runtime::audit::append(
        "scan",
        &json!({"paths": positionals, "fields": fields, "files_read": walk.files_read.len(), "found": walk.found.len()}),
    )?;
    if flag_set(flags, "refuse") && !walk.found.is_empty() {
        let copies: Vec<String> = walk
            .found
            .iter()
            .map(|copy| {
                format!(
                    "{}:{} holds {}'s {}",
                    copy.file, copy.line, copy.item, copy.field
                )
            })
            .collect();
        bail!("a vault value is in plain text: {}; remove each copy, or keep the value in the vault and read it through skarbiec exec or inject", copies.join("; "));
    }
    let found: Vec<Value> = walk
        .found
        .iter()
        .map(|copy| json!({"file": copy.file, "line": copy.line, "item": copy.item, "field": copy.field}))
        .collect();
    Ok(Some(json!({
        "ok": found.is_empty() && walk.unreadable.is_empty() && unreadable_items.is_empty(),
        "paths": positionals,
        "fields": fields,
        "values_compared": held.len(),
        "below_min_length": below_minimum,
        "files_read": walk.files_read.len(),
        "found": found,
        "unreadable_files": walk.unreadable,
        "unreadable_items": unreadable_items,
    })))
}

/// The fields a scan looks for and the shortest value it compares, as
/// --fields and --min-length state them.
fn requested<'f>(
    flags: &'f HashMap<String, String>,
    usage: &str,
) -> Result<(Vec<&'f str>, Option<usize>)> {
    let fields: Vec<&str> = flags
        .get("fields")
        .or_usage(usage)?
        .split(',')
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .collect();
    if fields.is_empty() {
        return Err(Usage(format!("--fields names no field; {usage}")).into());
    }
    let minimum = match flags.get("min-length") {
        Some(given) => Some(
            given
                .parse::<usize>()
                .with_context(|| format!("--min-length {given} is not a whole number"))?,
        ),
        None => None,
    };
    Ok((fields, minimum))
}

/// Every non-empty text value the named fields hold across the live items;
/// an item that will not open is named with its error, never skipped.
fn values(fields: &[&str], minimum: Option<usize>) -> Result<(Vec<Held>, Vec<Value>, Vec<Value>)> {
    let vault = Vault::open(vault_path())?;
    let mut held = Vec::new();
    let mut unreadable = Vec::new();
    let mut below = Vec::new();
    for entry in vault.list(false) {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        if entry.get("state").and_then(Value::as_str) != Some("active") {
            continue;
        }
        let opened = vault
            .get_item(id)
            .and_then(|payload| schema::fields(&payload).cloned());
        let held_fields = match opened {
            Ok(held_fields) => held_fields,
            Err(error) => {
                unreadable.push(json!({"item": id, "error": format!("{error:#}")}));
                continue;
            }
        };
        for field in fields {
            let Some(text) = held_fields
                .get(*field)
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
            else {
                continue;
            };
            if minimum.is_some_and(|minimum| text.chars().count() < minimum) {
                below.push(json!({"item": id, "field": field}));
                continue;
            }
            held.push(Held {
                item: id.to_string(),
                field: field.to_string(),
                value: text.to_string(),
            });
        }
    }
    Ok((held, unreadable, below))
}

/// One path: a directory's entries in turn, a regular file compared with
/// every value, a symbolic link left alone.
fn visit(path: &Path, held: &[Held], walk: &mut Walk) {
    let shown = path.display().to_string();
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return walk
                .unreadable
                .push(json!({"path": shown, "error": error.to_string()}))
        }
    };
    if metadata.is_dir() {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) => {
                return walk
                    .unreadable
                    .push(json!({"path": shown, "error": error.to_string()}))
            }
        };
        for entry in entries {
            match entry {
                Ok(entry) => visit(&entry.path(), held, walk),
                Err(error) => walk
                    .unreadable
                    .push(json!({"path": shown, "error": error.to_string()})),
            }
        }
        return;
    }
    if !metadata.is_file() {
        return;
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return walk
                .unreadable
                .push(json!({"path": shown, "error": error.to_string()}))
        }
    };
    for held_value in held {
        let needle = held_value.value.as_bytes();
        if let Some(at) = bytes
            .windows(needle.len())
            .position(|window| window == needle)
        {
            // The line the copy starts on: the lines of everything before it.
            let line = bytes[..at].split(|byte| *byte == b'\n').count();
            walk.found.push(PlainCopy {
                file: shown.clone(),
                line,
                item: held_value.item.clone(),
                field: held_value.field.clone(),
            });
        }
    }
    walk.files_read.push(shown);
}
