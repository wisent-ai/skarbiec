// `password age [<id>] [--set-before <iso>]`: when each live login's password was
// last set — the save that first held it, or the last one that changed it —
// oldest first, so a rotation starts with the passwords that have stood the
// longest. Saved versions are opened to compare and only the moment leaves:
// no value, length or digest. A version that will not open is named with its
// error and the comparison runs past it.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::Usage;
use crate::core::{clock, vault::Vault, vault_path};

/// The login schema's secret field, whose age this command reports.
const PASSWORD: &str = "password";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    let Some(positionals) = crate::cli::args::verb(command, positionals, "password", "age") else {
        return Ok(None);
    };
    const USAGE: &str = "usage: password age [<id>] [--set-before <iso8601>]";
    match positionals {
        [] => report(flags.get("set-before").map(String::as_str)).map(Some),
        // One item, as its inspector asks: no moment to compare with.
        [id] if !flags.contains_key("set-before") => of(id).map(Some),
        _ => Err(Usage(USAGE.to_string()).into()),
    }
}

/// When one item's password was last set, as `password age <id>` and
/// `POST /v1/operator/items/password-age` with id answer it.
pub fn of(id: &str) -> Result<Value> {
    last_set(&Vault::open(vault_path())?, id)
}

/// Every live login with the moment its password was last set; with
/// `set_before`, only the ones set before it. Called by the command line,
/// `POST /v1/operator/items/password-age` and `review`.
pub fn report(set_before: Option<&str>) -> Result<Value> {
    if let Some(moment) = set_before {
        if !clock::is_iso(moment) {
            return Err(Usage(format!(
                "--set-before {moment} is not a UTC time of the form {}",
                clock::now_iso()
            ))
            .into());
        }
    }
    let vault = Vault::open(vault_path())?;
    let mut rows = Vec::new();
    for entry in vault.list(false) {
        if entry.get("kind").and_then(Value::as_str) != Some("login") {
            continue;
        }
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .context("a listed item records no id")?;
        let row = match last_set(&vault, id) {
            Ok(row) => row,
            Err(error) => json!({"id": id, "set_at": Value::Null, "error": format!("{error:#}")}),
        };
        let keep = match (set_before, row.get("set_at").and_then(Value::as_str)) {
            (Some(moment), Some(at)) => at < moment,
            (Some(_), None) => row.get("error").is_some(),
            (None, _) => true,
        };
        if keep {
            rows.push(row);
        }
    }
    rows.sort_by(|left, right| {
        left.get("set_at")
            .and_then(Value::as_str)
            .cmp(&right.get("set_at").and_then(Value::as_str))
    });
    Ok(json!({"ok": true, "set_before": set_before, "logins": rows}))
}

/// When `id`'s password was last set, with any saved version that would
/// not open named under `unreadable`.
fn last_set(vault: &Vault, id: &str) -> Result<Value> {
    let versions = vault.versions(id)?;
    let first = versions
        .get("versions")
        .and_then(Value::as_array)
        .and_then(|all| all.first())
        .and_then(|version| version.get("at"))
        .cloned()
        .with_context(|| format!("{id} keeps no version to date its password from"))?;
    let changes = vault.version_changes(id)?;
    let mut set_at = first;
    let mut unreadable = Vec::new();
    for change in changes
        .get("changes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(error) = change.get("error") {
            unreadable.push(json!({"at": change.get("at"), "error": error}));
            continue;
        }
        let names = |member: &str| -> bool {
            change
                .get(member)
                .and_then(Value::as_array)
                .is_some_and(|names| names.iter().any(|name| name.as_str() == Some(PASSWORD)))
        };
        if names("added") || names("changed") {
            if let Some(at) = change.get("at") {
                set_at = at.clone();
            }
        }
    }
    Ok(json!({"id": id, "set_at": set_at, "unreadable": unreadable}))
}
