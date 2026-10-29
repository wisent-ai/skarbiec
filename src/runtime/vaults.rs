// What vaults this machine holds.
//
// A vault is a file, not an entry in a registry, so "which vaults are here"
// has no authoritative answer - only the conventional places vaults get
// written. Reading them is cheap and safe: every value is a PGP message, and
// the counts below come from the plaintext envelope without decrypting
// anything.
//
// No item name is ever reported. `docs/PRODUCT.md` is blunt that names of
// secrets, consumers and scopes are the cleartext map, and a command built to
// be run across a fleet is the last place to widen that exposure.

use anyhow::Result;
use serde_json::{json, Value};
use std::path::PathBuf;

const SUFFIX: &str = ".vault.json";

/// Directories this product and its own examples write vaults into. HOME
/// unset is refused, because no directory list could then support a claim
/// that this machine holds no vault.
fn search_directories() -> Result<Vec<PathBuf>> {
    let home = std::env::home_dir()
        .filter(|home| !home.as_os_str().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("HOME is not set, so the directories vaults are written to are unknown")
        })?;
    Ok(vec![
        home.join(".local/share/skarbiec"),
        home.join(".stado"),
        home,
    ])
}

/// Parse one `.vault.json`: the suffix `Vault::create` writes is what makes
/// a file a vault. One that cannot be read, does not parse, or whose root is
/// not an object is the error, with its cause, so the inventory lists it as
/// unreadable instead of leaving it out. A count or owner the file does not
/// hold is reported as null rather than as zero or an empty owner, and the
/// item count comes back beside the row so the inventory sorts on it.
fn read(path: &PathBuf) -> std::result::Result<(Option<usize>, Value), String> {
    let raw = std::fs::read_to_string(path).map_err(|error| format!("cannot be read: {error}"))?;
    let document: Value =
        serde_json::from_str(&raw).map_err(|error| format!("is not valid JSON: {error}"))?;
    let object = document
        .as_object()
        .ok_or_else(|| "does not hold a JSON object".to_string())?;
    let count = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_object)
            .map(serde_json::Map::len)
    };
    let items = count("items");
    Ok((
        items,
        json!({
            "path": path.display().to_string(),
            "owner": object.get("owner").and_then(Value::as_str),
            "items": items,
            "recipients": count("recipients"),
            "tokens": count("tokens"),
        }),
    ))
}

/// Every vault in the conventional locations, largest first, and every
/// candidate that could not be read (`unreadable`, with its path and cause):
/// a directory or vault file this process cannot read is reported, never
/// counted as no vault.
pub fn inventory() -> Result<Value> {
    let directories = search_directories()?;
    let mut seen: Vec<String> = Vec::new();
    let mut found: Vec<(Option<usize>, String, Value)> = Vec::new();
    let mut unreadable: Vec<Value> = Vec::new();
    for directory in &directories {
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                unreadable.push(json!({
                    "path": directory.display().to_string(),
                    "cause": format!("cannot be listed: {error}"),
                }));
                continue;
            }
        };
        for entry in entries {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(error) => {
                    unreadable.push(json!({
                        "path": directory.display().to_string(),
                        "cause": format!("an entry cannot be read: {error}"),
                    }));
                    continue;
                }
            };
            let name = path.file_name().and_then(std::ffi::OsStr::to_str);
            if !name.is_some_and(|name| name.ends_with(SUFFIX)) {
                continue;
            }
            match std::fs::metadata(&path) {
                Ok(metadata) if metadata.is_file() => {}
                Ok(_) => continue,
                Err(error) => {
                    unreadable.push(json!({
                        "path": path.display().to_string(),
                        "cause": format!("metadata cannot be read: {error}"),
                    }));
                    continue;
                }
            }
            let key = path.display().to_string();
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            match read(&path) {
                Ok((items, vault)) => found.push((items, path.display().to_string(), vault)),
                Err(cause) => unreadable.push(json!({
                    "path": path.display().to_string(),
                    "cause": cause,
                })),
            }
        }
    }
    // Largest first, then by path; a vault holding no items map sorts last.
    found.sort_by(|(left_items, left_path, _), (right_items, right_path, _)| {
        right_items
            .cmp(left_items)
            .then_with(|| left_path.cmp(right_path))
    });
    let found: Vec<Value> = found.into_iter().map(|(_, _, vault)| vault).collect();
    Ok(json!({
        "host": hostname()?,
        "searched": directories
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<String>>(),
        "shared_owners": shared_owners(&found),
        "vaults": found,
        "unreadable": unreadable,
    }))
}

/// Every owner more than one vault file here claims, with those files and
/// the command that joins a copy into the one Stado declares. Two files of
/// one owner leave owner resolution with no single answer, and native
/// signing refuses until they are reconciled.
fn shared_owners(found: &[Value]) -> Vec<Value> {
    let mut by_owner: std::collections::BTreeMap<&str, Vec<&str>> =
        std::collections::BTreeMap::new();
    for vault in found {
        if let (Some(owner), Some(path)) = (vault["owner"].as_str(), vault["path"].as_str()) {
            by_owner.entry(owner).or_default().push(path);
        }
    }
    by_owner
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(owner, paths)| {
            json!({
                "owner": owner,
                "paths": paths,
                "join": "skarbiec migrate --from <the copy> --to <the vault Stado declares> --reconcile",
            })
        })
        .collect()
}

/// The machine's own name, so a fleet-wide collection can say where each
/// answer came from without the collector having to label it. A name that
/// cannot be read is the inventory's error with its cause: an invented label
/// would file this machine's vaults under a host that does not exist.
pub(crate) fn hostname() -> Result<String> {
    let output = stado_wait::output(&mut std::process::Command::new("hostname"))
        .map_err(|error| anyhow::anyhow!("the hostname program could not run: {error}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "the hostname program ended with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let name = String::from_utf8(output.stdout).map_err(|error| {
        anyhow::anyhow!("the hostname program answered a name that is not UTF-8: {error}")
    })?;
    let name = name.trim();
    if name.is_empty() {
        anyhow::bail!("the hostname program answered no name");
    }
    Ok(name.to_string())
}
