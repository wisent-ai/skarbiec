// The bindings files this host knows of: every file an import bound a token
// in (tool import and env import --bindings remember the file they
// write), and any a developer names with
// `bindings remember <file>`. Knowing them lets `rename` rebind each line
// naming the old id, `doctor` check every line still gives its program a
// value, and `bindings list` say so in one place. The record lives beside
// the vault file in `<vault file>.bindings.json`, as the kept CI secrets do:
// it is this host's, names files, and never holds a value.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use crate::core::vault_path;

fn store() -> PathBuf {
    let mut name = vault_path().into_os_string();
    name.push(".bindings.json");
    PathBuf::from(name)
}

fn read() -> Result<Vec<String>> {
    let path = store();
    match crate::core::read_present(&path, "known bindings files")? {
        Some(text) => serde_json::from_str(&text)
            .with_context(|| format!("{} is not a JSON list of bindings files", path.display())),
        None => Ok(Vec::new()),
    }
}

fn write(files: &[String]) -> Result<()> {
    let path = store();
    let body = serde_json::to_vec_pretty(files).context("render the known bindings files")?;
    crate::core::vault::atomic_write(&path, &body)
        .with_context(|| format!("write {}", path.display()))
}

/// The file as it is recorded: absolute, from the working directory.
fn absolute(file: &Path) -> Result<String> {
    Ok(std::env::current_dir()
        .context("read the working directory")?
        .join(file)
        .display()
        .to_string())
}

/// Remember `file`; answers whether it was new.
pub(crate) fn remember(file: &Path) -> Result<bool> {
    let shown = absolute(file)?;
    let mut files = read()?;
    if files.contains(&shown) {
        return Ok(false);
    }
    files.push(shown);
    write(&files)?;
    Ok(true)
}

pub(super) fn remember_value(file: &str) -> Result<Value> {
    let shown = absolute(Path::new(file))?;
    // A file that does not name a single binding is refused, so a typo is
    // not remembered as a file doctor then fails on.
    crate::runtime::exec::bindings_in(&shown)
        .with_context(|| format!("{shown} is not a bindings file exec --env-from reads"))?;
    let added = remember(Path::new(&shown))?;
    crate::runtime::audit::append(
        "bindings-remembered",
        &json!({"file": shown, "added": added}),
    )?;
    Ok(json!({"ok": true, "file": shown, "added": added}))
}

pub(super) fn forget(file: &str) -> Result<Value> {
    let shown = absolute(Path::new(file))?;
    let mut files = read()?;
    let before = files.len();
    files.retain(|known| known != &shown);
    if files.len() == before {
        bail!(
            "{shown} is not a bindings file this host knows of; bindings list names those it does"
        );
    }
    write(&files)?;
    crate::runtime::audit::append("bindings-forgotten", &json!({"file": shown}))?;
    Ok(json!({"ok": true, "file": shown}))
}

/// Each known file with whether every line gives its program a value, the
/// failing variables with why, or why the file could not be read.
pub(crate) fn report() -> Result<Vec<Value>> {
    Ok(read()?
        .into_iter()
        .map(|file| match super::rows(&file) {
            Ok(rows) => {
                let failing: Vec<Value> = rows.iter().filter(|row| row["ok"] == json!(false)).cloned().collect();
                json!({"file": file, "bindings": rows.len(), "ok": failing.is_empty(), "failing": failing})
            }
            Err(error) => json!({"file": file, "ok": false, "failing": [], "error": format!("{error:#}")}),
        })
        .collect())
}

pub(super) fn list() -> Result<Value> {
    let files = report()?;
    let ok = files.iter().all(|file| file["ok"] == json!(true));
    Ok(json!({"ok": ok, "store": store(), "files": files}))
}

/// `text` with every binding of `from` bound to `to`; None when no line
/// names `from`. Comment lines stay as they are.
pub(crate) fn rebound(text: &str, from: &str, to: &str) -> Option<String> {
    let old = format!("={from}:");
    let mut changed = false;
    let lines: Vec<String> = text
        .lines()
        .map(
            |line| match (line.trim_start().starts_with('#'), line.split_once(&old)) {
                (false, Some((name, field))) => {
                    changed = true;
                    format!("{name}={to}:{field}")
                }
                _ => line.to_string(),
            },
        )
        .collect();
    let mut out = lines.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    changed.then_some(out)
}

/// Rebind `from` to `to` in `file`; answers whether the file changed.
pub(crate) fn rebind_file(file: &str, from: &str, to: &str) -> Result<bool> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("read the bindings file {file}"))?;
    match rebound(&text, from, to) {
        Some(out) => {
            crate::core::vault::atomic_write(Path::new(file), out.as_bytes()).map(|_| true)
        }
        None => Ok(false),
    }
}

/// Rebind `from` to `to` in every known file, answering the files moved and
/// those that could not be, each with why.
pub(crate) fn follow_rename(from: &str, to: &str) -> Result<Value> {
    let mut moved: Vec<String> = Vec::new();
    let mut not_moved: Vec<Value> = Vec::new();
    for file in read()? {
        match rebind_file(&file, from, to) {
            Ok(true) => moved.push(file),
            Ok(false) => {}
            Err(error) => not_moved.push(json!({"file": file, "error": format!("{error:#}")})),
        }
    }
    Ok(json!({"moved": moved, "not_moved": not_moved}))
}
