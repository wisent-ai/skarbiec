// `skarbiec bindings check <file> [--refuse]`: say, for every NAME=<id>:<field>
// line of a bindings file `exec --env-from` reads, whether the program would
// get a value — the item is live, opens here and holds text in that field —
// or why not: no such item, an item in the trash, a field it does not hold,
// or the error opening it gave. A project commits its bindings file while an
// item it names is renamed, trashed or rotated into another shape; this finds
// the line that would break `exec` before a deploy does. No value is printed;
// with --refuse a line that would fail makes the command fail, for CI.
// `bindings list | remember <file> | forget <file>` keep the files this host
// knows of, so rename rebinds them and doctor checks them (known.rs).

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::{flag_set, Usage};
use crate::core::{vault::Vault, vault_path};

mod known;
pub(crate) use known::{follow_rename, rebind_file, remember, report as known_report};

const USAGE: &str = "usage: bindings check <file> [--refuse] | bindings list | bindings remember <file> | bindings forget <file>";

pub fn dispatch(command: &str, flags: &HashMap<String, String>, positionals: &[String]) -> Result<Option<Value>> {
    if command != "bindings" {
        return Ok(None);
    }
    match positionals {
        [leaf, file] if leaf == "check" => check(file, flag_set(flags, "refuse")).map(Some),
        [leaf] if leaf == "list" => known::list().map(Some),
        [leaf, file] if leaf == "remember" => known::remember_value(file).map(Some),
        [leaf, file] if leaf == "forget" => known::forget(file).map(Some),
        _ => Err(Usage(USAGE.to_string()).into()),
    }
}

/// Why one binding would give its program nothing, or None when it would
/// give a value.
fn problem(vault: &Vault, live: &[String], trashed: &[String], item: &str, field: &str) -> Option<String> {
    if trashed.iter().any(|held| held == item) {
        return Some(format!("{item} is in the trash; restore {item} or bind another item"));
    }
    if !live.iter().any(|held| held == item) {
        return Some(format!("no item {item}; it may have been renamed or purged"));
    }
    match vault.get_item(item) {
        Err(error) => Some(format!("{item} would not open here: {error:#}")),
        Ok(payload) => match payload["fields"][field].as_str() {
            Some(text) if !text.is_empty() => None,
            Some(_) => Some(format!("{item}'s {field} is empty")),
            None => Some(format!("{item} holds no text field {field}")),
        },
    }
}

/// Each binding of the file at `shown`, marked with whether its program would
/// get a value and, when not, the problem. Journals nothing, so doctor can
/// ask on every run.
pub(crate) fn rows(shown: &str) -> Result<Vec<Value>> {
    let bindings = crate::runtime::exec::bindings_in(shown)?;
    let vault = Vault::open(vault_path())?;
    let ids = |state_trashed: bool| -> Vec<String> {
        vault
            .list(state_trashed)
            .iter()
            .filter(|item| (item.get("state").and_then(Value::as_str) == Some("trashed")) == state_trashed)
            .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
            .collect()
    };
    let live = ids(false);
    let trashed = ids(true);
    Ok(bindings
        .iter()
        .map(|binding| match problem(&vault, &live, &trashed, &binding.item, &binding.field) {
            None => json!({"variable": binding.name, "item": binding.item, "field": binding.field, "ok": true}),
            Some(why) => json!({"variable": binding.name, "item": binding.item, "field": binding.field, "ok": false, "problem": why}),
        })
        .collect())
}

fn check(file: &str, refuse: bool) -> Result<Value> {
    let here = std::env::current_dir().context("read the working directory")?;
    let shown = here.join(file).display().to_string();
    let rows = rows(&shown)?;
    let failing: Vec<&str> = rows.iter().filter(|row| row["ok"] == json!(false)).filter_map(|row| row["variable"].as_str()).collect();
    crate::runtime::audit::append("bindings-checked", &json!({"file": shown, "failing": failing}))?;
    if refuse && !failing.is_empty() {
        bail!("{shown}: exec would give {} nothing — {}", failing.join(", "), rows.iter().filter_map(|row| row["problem"].as_str()).collect::<Vec<_>>().join("; "));
    }
    Ok(json!({"ok": failing.is_empty(), "file": shown, "bindings": rows}))
}
