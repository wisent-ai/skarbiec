// `retag --rename <old> --to <new>`: one tag renamed on every live item that
// carries it, the way a namespace or a role is renamed — instead of one
// `retag <id> --tags` per item, each restating the whole list. `--to ""`
// drops the tag. An item the owner may not retag directly (lifecycle
// controlled, or this host a replica) is named with the reason and left as
// it is; every other one is retagged.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;
use crate::core::vault_path;

pub(crate) mod members;

use super::args::{OrUsage, Usage};
use super::items::{ensure_no_reserved_tags, ensure_owner_mutation_allowed};

pub(crate) fn rename_tag(flags: &HashMap<String, String>) -> Result<Value> {
    let from = flags
        .get("rename")
        .map(|tag| tag.trim())
        .filter(|tag| !tag.is_empty())
        .or_usage("usage: retag --rename <tag> --to <tag> (--to \"\" drops it)")?;
    let to = flags
        .get("to")
        .map(|tag| tag.trim())
        .or_usage("usage: retag --rename <tag> --to <tag> (--to \"\" drops it)")?;
    if from == to {
        return Err(Usage(format!("--rename and --to both name {from}; there is nothing to rename")).into());
    }
    if !to.is_empty() {
        ensure_no_reserved_tags(&[to.to_string()])?;
    }
    let mut vault = Vault::open(vault_path())?;
    let carrying: Vec<(String, Vec<String>)> = vault
        .list(false)
        .iter()
        .filter_map(|item| {
            let id = item.get("id").and_then(Value::as_str)?;
            let tags: Vec<String> = item
                .get("tags")
                .and_then(Value::as_array)?
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
            tags.iter().any(|tag| tag == from).then(|| (id.to_string(), tags))
        })
        .collect();
    if carrying.is_empty() {
        return Err(Usage(format!("no live item carries the tag {from}, so nothing was renamed")).into());
    }
    let mut retagged = Vec::new();
    let mut not_retagged = Vec::new();
    for (id, tags) in carrying {
        if let Err(error) = ensure_owner_mutation_allowed(&vault, &id, "retag") {
            not_retagged.push(json!({"id": id, "error": format!("{error:#}")}));
            continue;
        }
        let mut renamed: Vec<String> = Vec::new();
        for tag in tags {
            let tag = if tag == from { to.to_string() } else { tag };
            if !tag.is_empty() && !renamed.contains(&tag) {
                renamed.push(tag);
            }
        }
        match vault.set_item_tags(&id, &renamed) {
            Ok(_) => retagged.push(json!({"id": id, "tags": renamed})),
            Err(error) => not_retagged.push(json!({"id": id, "error": format!("{error:#}")})),
        }
    }
    // A grant may name a role an item plays through its stado:role: tag;
    // renaming that tag leaves the grant naming a role nothing plays, so the
    // answer lists every grant that now names something nothing answers.
    let dangling = crate::access::dispatch(
        "grant",
        &HashMap::from([("dangling".to_string(), "true".to_string())]),
        &["list".to_string()],
    )?;
    Ok(json!({
        "ok": not_retagged.is_empty(),
        "from": from,
        "to": to,
        "retagged": retagged,
        "not_retagged": not_retagged,
        "grants_naming_missing_items": dangling,
    }))
}
