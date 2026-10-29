// `skarbiec scan <repo> --history --fields <field,...> [--min-length <N>]`:
// the commits of a repository, on every branch, that added a line holding a
// vault value. A copy already committed stays in history after the file is
// fixed, so each one found is a value to replace, not only a file to clean:
// the answer names the commit, the file, the item and the field, and the
// replace step, never the value. Only added lines are compared.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::process::Command;

use crate::cli::args::Usage;

const USAGE: &str = "usage: scan <repo> --history --fields <field,...> [--min-length <N>]";
const COMMIT: &[u8] = b"commit ";
const NEW_FILE: &[u8] = b"+++ b/";
const ADDED: &[u8] = b"+";
const HEADER: &[u8] = b"+++";

pub(super) fn run(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let [repo] = positionals else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let (fields, minimum) = super::requested(flags, USAGE)?;
    let (held, unreadable_items, below_minimum) = super::values(&fields, minimum)?;
    let repo = std::env::current_dir()
        .context("read the working directory")?
        .join(repo);
    let log = stado_wait::output(Command::new("git").arg("-C").arg(&repo).args([
        "log",
        "--all",
        "-p",
        "--no-color",
        "--no-ext-diff",
        "--format=commit %H",
    ]))
    .context("run git log, which reads the repository's history")?;
    if !log.status.success() {
        bail!(
            "git log could not read {} ({}): {}",
            repo.display(),
            log.status,
            String::from_utf8_lossy(&log.stderr).trim()
        );
    }
    let mut commits = BTreeSet::new();
    let mut found = BTreeSet::new();
    let mut commit = String::new();
    let mut file = String::new();
    for line in log.stdout.split(|byte| *byte == b'\n') {
        if let Some(hash) = line.strip_prefix(COMMIT) {
            commit = String::from_utf8_lossy(hash).into_owned();
            commits.insert(commit.clone());
            continue;
        }
        if let Some(path) = line.strip_prefix(NEW_FILE) {
            file = String::from_utf8_lossy(path).into_owned();
            continue;
        }
        if line.starts_with(HEADER) || !line.starts_with(ADDED) {
            continue;
        }
        for copy in &held {
            let needle = copy.value.as_bytes();
            if line.windows(needle.len()).any(|window| window == needle) {
                found.insert((
                    commit.clone(),
                    file.clone(),
                    copy.item.clone(),
                    copy.field.clone(),
                ));
            }
        }
    }
    let found: Vec<Value> = found
        .into_iter()
        .map(|(commit, file, item, field)| {
            json!({
                "commit": commit,
                "file": file,
                "item": item,
                "field": field,
                "repair": format!("the value is in history for good: replace {item}'s {field} where it is issued, then store the new one"),
            })
        })
        .collect();
    crate::runtime::audit::append(
        "scan-history",
        &json!({"repo": repo.display().to_string(), "fields": fields, "commits_read": commits.len(), "found": found.len()}),
    )?;
    Ok(json!({
        "ok": found.is_empty() && unreadable_items.is_empty(),
        "repo": repo.display().to_string(),
        "fields": fields,
        "values_compared": held.len(),
        "below_min_length": below_minimum,
        "commits_read": commits.len(),
        "found": found,
        "unreadable_items": unreadable_items,
    }))
}
