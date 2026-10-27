// `retag --add <tag> <id> [<id>...]` and `retag --remove <tag> <id>
// [<id>...]`: put one tag on, or take it off, several items at once, leaving
// every other tag each carries as it is — how a contractor's or a project's
// set is gathered before share --tag, delete --tag, restore --tag or expiry
// set --tag act on it, without restating each item's whole list. An item
// that is not live, or that the owner may not retag directly, is named with
// the reason and left as it is; every other one is retagged.

use anyhow::Result;
use serde_json::{json, Value};

use crate::core::vault::Vault;
use crate::core::vault_path;

use super::super::args::Usage;
use super::super::items::{ensure_no_reserved_tags, ensure_owner_mutation_allowed};

/// Whether the tag goes on the items or comes off them.
pub(crate) enum Change {
    Add,
    Remove,
}

pub(crate) fn change_tag(change: Change, tag: &str, ids: &[String]) -> Result<Value> {
    let tag = tag.trim();
    if tag.is_empty() || ids.is_empty() {
        return Err(Usage("usage: retag --add <tag> <id> [<id>...] | retag --remove <tag> <id> [<id>...]".to_string()).into());
    }
    if matches!(change, Change::Add) {
        ensure_no_reserved_tags(&[tag.to_string()])?;
    }
    let mut vault = Vault::open(vault_path())?;
    let live = vault.list(false);
    let mut retagged = Vec::new();
    let mut unchanged = Vec::new();
    let mut not_retagged = Vec::new();
    for id in ids {
        let Some(held) = live.iter().find(|item| item.get("id").and_then(Value::as_str) == Some(id.as_str())) else {
            not_retagged.push(json!({"id": id, "error": format!("{id} is not a live item")}));
            continue;
        };
        let tags: Vec<String> = held
            .get("tags")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        let carries = tags.iter().any(|held| held == tag);
        let next: Vec<String> = match change {
            Change::Add if carries => {
                unchanged.push(id.clone());
                continue;
            }
            Change::Remove if !carries => {
                unchanged.push(id.clone());
                continue;
            }
            Change::Add => tags.into_iter().chain(std::iter::once(tag.to_string())).collect(),
            Change::Remove => tags.into_iter().filter(|held| held != tag).collect(),
        };
        if let Err(error) = ensure_owner_mutation_allowed(&vault, id, "retag") {
            not_retagged.push(json!({"id": id, "error": format!("{error:#}")}));
            continue;
        }
        match vault.set_item_tags(id, &next) {
            Ok(_) => retagged.push(json!({"id": id, "tags": next})),
            Err(error) => not_retagged.push(json!({"id": id, "error": format!("{error:#}")})),
        }
    }
    Ok(json!({
        "ok": not_retagged.is_empty(),
        "tag": tag,
        "added": matches!(change, Change::Add),
        "retagged": retagged,
        "unchanged": unchanged,
        "not_retagged": not_retagged,
    }))
}
