// `skarbiec backup diff <file>`: what differs between a copy and the vault in
// use, read from both files' cleartext envelopes, so nothing is decrypted: the
// live items only the copy holds, the ones only the vault holds, and the ones
// both hold at different revisions, with each side's revision and when it was
// written. It answers which copy to restore, or whether one item is better
// taken back with `restore <id> --at`, before anything is replaced.

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use std::path::Path;

use crate::core::{vault::Vault, vault_path};

/// Each live item's envelope row, by id.
fn live(vault: &Vault) -> Map<String, Value> {
    vault
        .list(false)
        .into_iter()
        .filter_map(|row| Some((row.get("id")?.as_str()?.to_string(), row)))
        .collect()
}

pub(super) fn diff(file: &Path) -> Result<Value> {
    let copy = Vault::open(file.to_path_buf())
        .with_context(|| format!("{} does not read as a Skarbiec vault", file.display()))?;
    let current = Vault::open(vault_path())?;
    let (theirs, ours) = (live(&copy), live(&current));
    let side = |row: &Value| json!({"revision": row["revision"], "updated_at": row["updated_at"]});
    let only_in_copy: Vec<Value> = theirs
        .iter()
        .filter(|(id, _)| !ours.contains_key(*id))
        .map(|(id, row)| json!({"item": id, "copy": side(row)}))
        .collect();
    let only_in_vault: Vec<Value> = ours
        .iter()
        .filter(|(id, _)| !theirs.contains_key(*id))
        .map(|(id, row)| json!({"item": id, "vault": side(row)}))
        .collect();
    let changed: Vec<Value> = theirs
        .iter()
        .filter_map(|(id, copied)| {
            let held = ours.get(id)?;
            (copied["revision"] != held["revision"]).then(|| json!({"item": id, "copy": side(copied), "vault": side(held)}))
        })
        .collect();
    Ok(json!({
        "ok": true,
        "file": file.display().to_string(),
        "only_in_copy": only_in_copy,
        "only_in_vault": only_in_vault,
        "changed": changed,
        "same": theirs.keys().filter(|id| ours.get(*id).is_some_and(|held| held["revision"] == theirs[*id]["revision"])).count(),
    }))
}
