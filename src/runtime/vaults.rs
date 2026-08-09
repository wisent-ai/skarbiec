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

/// The keys `Vault::create` writes. A file missing any of them is some other
/// JSON that happens to sit in the same directory.
const REQUIRED_KEYS: [&str; 5] = ["version", "owner", "recovery", "recipients", "items"];

const SUFFIX: &str = ".vault.json";

/// Directories this product and its own examples write vaults into.
fn search_directories() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    vec![
        home.join(".local/share/skarbiec"),
        home.join(".stado"),
        home,
    ]
}

/// Parse one candidate, or decide it is not a vault. A backup or a
/// half-written file is simply absent from the list rather than an error the
/// caller has to interpret.
fn read(path: &PathBuf) -> Option<Value> {
    let raw = std::fs::read_to_string(path).ok()?;
    let document: Value = serde_json::from_str(&raw).ok()?;
    let object = document.as_object()?;
    if !REQUIRED_KEYS.iter().all(|key| object.contains_key(*key)) {
        return None;
    }
    let count = |key: &str| -> usize {
        object
            .get(key)
            .and_then(Value::as_object)
            .map(serde_json::Map::len)
            .unwrap_or_default()
    };
    Some(json!({
        "path": path.display().to_string(),
        "owner": object.get("owner").and_then(Value::as_str).unwrap_or_default(),
        "items": count("items"),
        "recipients": count("recipients"),
        "tokens": count("tokens"),
    }))
}

/// Every vault in the conventional locations, largest first.
pub fn inventory() -> Result<Value> {
    let mut seen: Vec<String> = Vec::new();
    let mut found: Vec<Value> = Vec::new();
    for directory in search_directories() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = path.file_name().and_then(std::ffi::OsStr::to_str);
            if !name.is_some_and(|name| name.ends_with(SUFFIX)) {
                continue;
            }
            let key = path.display().to_string();
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            if let Some(vault) = read(&path) {
                found.push(vault);
            }
        }
    }
    found.sort_by(|left, right| {
        let items = |value: &Value| {
            value
                .get("items")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        };
        items(right).cmp(&items(left)).then_with(|| {
            let path = |value: &Value| {
                value
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            path(left).cmp(&path(right))
        })
    });
    Ok(json!({
        "host": hostname(),
        "searched": search_directories()
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<String>>(),
        "vaults": found,
    }))
}

/// The machine's own name, so a fleet-wide collection can say where each
/// answer came from without the collector having to label it.
fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}
