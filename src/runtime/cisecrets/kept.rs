// `ci keep <target> <place> --env-from <file> [...]` sets the secrets
// now and records the target on this host, so every `skarbiec maintain`
// pass sets them again once an item the bindings name has a new revision —
// a rotation reaches CI and the cluster without anyone remembering to.
// `ci kept` lists what is kept and which items changed since;
// `ci forget <target> <place>` stops it. The record names the
// bindings file and each item's revision at the last set, never a value,
// and lives beside the vault file in `<vault file>.ci-secrets.json`, as
// the backup schedule does: it is this host's, not the vault's.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::core::{vault::Vault, vault_path};

const BINDINGS: &str = "env-from";
const YES: &str = "yes";

pub(super) fn store(vault: &Path) -> PathBuf {
    let mut name = vault.as_os_str().to_owned();
    name.push(".ci-secrets.json");
    PathBuf::from(name)
}

pub(super) fn read(path: &Path) -> Result<Vec<Value>> {
    match crate::core::read_present(path, "kept CI secrets")? {
        Some(text) => serde_json::from_str(&text)
            .with_context(|| format!("{} is not a JSON list of kept targets", path.display())),
        None => Ok(Vec::new()),
    }
}

pub(super) fn write(path: &Path, entries: &[Value]) -> Result<()> {
    let body = serde_json::to_vec_pretty(entries).context("render the kept CI secrets")?;
    crate::core::vault::atomic_write(path, &body)
        .with_context(|| format!("write {}", path.display()))
}

/// Each item the bindings name, with its revision now.
fn revisions(bindings: &str) -> Result<Map<String, Value>> {
    let vault = Vault::open(vault_path())?;
    let mut revisions = Map::new();
    for binding in crate::runtime::exec::bindings_in(bindings)? {
        revisions.insert(
            binding.item.clone(),
            json!(vault.item_revision(&binding.item)?),
        );
    }
    Ok(revisions)
}

/// The flags that set one kept target again: its bindings, the target's
/// own flags it was kept with, and yes.
fn flags_of(entry: &Value) -> Result<HashMap<String, String>> {
    let bindings = entry["bindings"]
        .as_str()
        .context("a kept target names no bindings file")?;
    let mut flags = HashMap::from([
        (BINDINGS.to_string(), bindings.to_string()),
        (YES.to_string(), "true".to_string()),
    ]);
    for (key, value) in entry["scope"].as_object().into_iter().flatten() {
        let value = value
            .as_str()
            .with_context(|| format!("a kept target's {key} is {value}, not text"))?;
        flags.insert(key.clone(), value.to_string());
    }
    Ok(flags)
}

fn same(entry: &Value, target: &str, place: &str) -> bool {
    entry["target"] == json!(target) && entry["place"] == json!(place)
}

pub(super) fn keep(target: &str, place: &str, flags: &HashMap<String, String>) -> Result<Value> {
    let given = flags
        .get(BINDINGS)
        .context("ci keep needs --env-from, the bindings file to set again")?;
    let bindings = std::env::current_dir()
        .context("read the working directory")?
        .join(given)
        .display()
        .to_string();
    // The target's own flags — an Actions environment, a kubectl context —
    // are kept as given; the bindings and the consent are not scope.
    let scope: Map<String, Value> = flags
        .iter()
        .filter(|(key, _)| key.as_str() != BINDINGS && key.as_str() != YES)
        .map(|(key, value)| (key.clone(), json!(value)))
        .collect();
    let mut entry = json!({"target": target, "place": place, "bindings": bindings, "scope": scope});
    let pushed = super::push(target, place, &flags_of(&entry)?)?;
    if pushed["ok"] != json!(true) {
        bail!(
            "{target} {place} was not set, so it is not kept: {}",
            pushed["refused"]
        );
    }
    entry["revisions"] = json!(revisions(&bindings)?);
    let path = store(&vault_path());
    let mut entries: Vec<Value> = read(&path)?
        .into_iter()
        .filter(|kept| !same(kept, target, place))
        .collect();
    entries.push(entry.clone());
    write(&path, &entries)?;
    crate::runtime::audit::append(
        "ci-secrets-kept",
        &json!({"target": target, "place": place, "bindings": bindings}),
    )?;
    Ok(json!({"ok": true, "kept": entry, "set": pushed}))
}

/// Every kept target, each with the items changed since it was last set.
pub(crate) fn list() -> Result<Value> {
    let mut listed = Vec::new();
    for entry in read(&store(&vault_path()))? {
        // The items whose revision moved since the last set; when they
        // cannot be read, null with the error beside it.
        let (changed, error) = match entry["bindings"].as_str().map(revisions) {
            Some(Ok(now)) => (
                json!(now
                    .iter()
                    .filter(|(item, revision)| entry["revisions"][item.as_str()] != **revision)
                    .map(|(item, _)| item)
                    .collect::<Vec<_>>()),
                Value::Null,
            ),
            Some(Err(error)) => (Value::Null, json!(format!("{error:#}"))),
            None => (Value::Null, json!("the kept target names no bindings file")),
        };
        listed.push(json!({
            "target": entry["target"],
            "place": entry["place"],
            "bindings": entry["bindings"],
            "scope": entry["scope"],
            "changed_since": changed,
            "error": error,
        }));
    }
    Ok(json!({"ok": true, "kept": listed}))
}

pub(super) fn forget(target: &str, place: &str) -> Result<Value> {
    let path = store(&vault_path());
    let entries = read(&path)?;
    if !entries.iter().any(|entry| same(entry, target, place)) {
        bail!("{target} {place} is not kept here; `skarbiec ci kept` lists what is");
    }
    let left: Vec<Value> = entries
        .into_iter()
        .filter(|entry| !same(entry, target, place))
        .collect();
    write(&path, &left)?;
    crate::runtime::audit::append(
        "ci-secrets-forgotten",
        &json!({"target": target, "place": place}),
    )?;
    Ok(json!({"ok": true, "target": target, "place": place, "kept": false}))
}

/// Set one kept target again when its items changed; false when none did.
fn renew(entry: &mut Value) -> Result<bool> {
    let bindings = entry["bindings"]
        .as_str()
        .context("the kept target names no bindings file")?
        .to_string();
    let now = revisions(&bindings)?;
    if entry["revisions"] == json!(now) {
        return Ok(false);
    }
    let target = entry["target"]
        .as_str()
        .context("the kept target names no target")?
        .to_string();
    let place = entry["place"]
        .as_str()
        .context("the kept target names no place")?
        .to_string();
    let pushed = super::push(&target, &place, &flags_of(entry)?)?;
    if pushed["ok"] != json!(true) {
        bail!("refused: {}", pushed["refused"]);
    }
    entry["revisions"] = json!(now);
    Ok(true)
}

/// The maintain step: set every kept target again whose items changed since
/// it was last set. None when this host keeps none.
pub fn pass() -> Result<Option<Value>> {
    let path = store(&vault_path());
    let mut entries = read(&path)?;
    if entries.is_empty() {
        return Ok(None);
    }
    let mut set = Vec::new();
    let mut unchanged = Vec::new();
    let mut failed = Vec::new();
    for entry in entries.iter_mut() {
        let named = format!("{} {}", entry["target"], entry["place"]);
        match renew(entry) {
            Ok(true) => set.push(named),
            Ok(false) => unchanged.push(named),
            Err(error) => failed.push(json!({"target": named, "error": format!("{error:#}")})),
        }
    }
    write(&path, &entries)?;
    Ok(Some(
        json!({"ok": failed.is_empty(), "set": set, "unchanged": unchanged, "failed": failed}),
    ))
}
