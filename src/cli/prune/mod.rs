// `purge <id> --versions-before <iso8601> [--yes]`: remove for good the saved
// versions of one item stamped before a moment — the passwords a site has
// long since replaced, which still open with the owner's key for anyone who
// gets the vault file and the key. `--all` instead of an id does it for every
// live item, naming each one the owner may not change and leaving it as it
// is. The current values and every later version stay, so restore --at still
// reaches them. Without --yes it only lists the stamps that would go; nothing
// undoes it once --yes runs.

use anyhow::Result;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::core::{clock, vault::Vault, vault_path};

use super::args::{flag_set, OrUsage, Usage};
use super::items::ensure_owner_mutation_allowed;

const USAGE: &str = "usage: purge <id> --versions-before <iso8601> [--yes] | purge --all --versions-before <iso8601> [--yes]";

pub(crate) fn purge_versions(
    flags: &HashMap<String, String>,
    positionals: &[String],
    before: &str,
) -> Result<Value> {
    let every = flag_set(flags, "all");
    let chosen: Option<&String> = match (positionals, every) {
        ([id], false) => Some(id),
        ([], true) => None,
        _ => return Err(Usage(USAGE.to_string()).into()),
    };
    if !clock::is_iso(before) {
        return Err(Usage(format!(
            "--versions-before {before} is not a UTC time of the form {}",
            clock::now_iso()
        ))
        .into());
    }
    let confirmed = flag_set(flags, "yes");
    let mut vault = Vault::open(vault_path())?;
    let Some(id) = chosen else {
        return purge_everywhere(&mut vault, before, confirmed);
    };
    ensure_owner_mutation_allowed(&vault, id, "remove versions of")?;
    let stamps = older_stamps(&vault, id, before)?;
    if !confirmed {
        return Ok(json!({"ok": true, "confirmed": false, "item": id, "would_forget": stamps}));
    }
    let forgotten = vault.forget_versions_before(id, before)?;
    if !forgotten.is_empty() {
        vault.save()?;
        crate::runtime::audit::append(
            "item-versions-purged",
            &json!({"item": id, "before": before, "versions": forgotten}),
        )?;
    }
    Ok(json!({"ok": true, "confirmed": true, "item": id, "forgotten": forgotten}))
}

/// The stamps of `id`'s saved versions older than `before`, oldest first.
fn older_stamps(vault: &Vault, id: &str, before: &str) -> Result<Vec<String>> {
    Ok(vault
        .versions(id)?
        .get("versions")
        .and_then(Value::as_array)
        .or_usage(USAGE)?
        .iter()
        .filter(|version| version.get("current").and_then(Value::as_bool) != Some(true))
        .filter_map(|version| version.get("at").and_then(Value::as_str))
        .filter(|at| *at < before)
        .map(str::to_string)
        .collect())
}

/// `--all`: every live item with an older saved version, item id -> stamps;
/// an item the owner may not change is named under `left` with the reason.
/// With `confirmed` they all go in one save and one audit entry.
fn purge_everywhere(vault: &mut Vault, before: &str, confirmed: bool) -> Result<Value> {
    let ids: Vec<String> = vault
        .list(false)
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let mut found = Map::new();
    let mut left = Vec::new();
    for id in &ids {
        let stamps = older_stamps(vault, id, before)?;
        if stamps.is_empty() {
            continue;
        }
        match ensure_owner_mutation_allowed(vault, id, "remove versions of") {
            Ok(()) => {
                found.insert(id.clone(), json!(stamps));
            }
            Err(error) => left.push(json!({"id": id, "error": format!("{error:#}")})),
        }
    }
    if !confirmed {
        return Ok(json!({"ok": true, "confirmed": false, "would_forget": found, "left": left}));
    }
    let mut forgotten = Map::new();
    for id in found.keys() {
        let gone = vault.forget_versions_before(id, before)?;
        if !gone.is_empty() {
            forgotten.insert(id.clone(), json!(gone));
        }
    }
    if !forgotten.is_empty() {
        vault.save()?;
        crate::runtime::audit::append(
            "versions-purged",
            &json!({"before": before, "items": forgotten}),
        )?;
    }
    Ok(json!({"ok": true, "confirmed": true, "forgotten": forgotten, "left": left}))
}
