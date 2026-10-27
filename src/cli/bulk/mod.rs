// `delete --tag <tag> [--yes]`: put every live item carrying one tag in the
// trash at once — a project that ended, a contractor's whole set — as share
// and revoke --tag act on the set. `restore --tag <tag> [--yes]` brings every
// trashed item carrying it back. Without --yes either only lists what it
// would move; every item is checked before any moves, so a refused one
// leaves the whole set where it was.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;
use crate::core::vault_path;

use super::args::{flag_set, Usage};
use super::items::ensure_owner_mutation_allowed;
use super::rename::grants_naming;

/// `delete` acting on a set: `--tag` or `--untouched-since`, never both;
/// None when the call names neither and so trashes one item by id.
pub(crate) fn delete_set(flags: &HashMap<String, String>) -> Option<Result<Value>> {
    match (flags.get("tag"), flags.get("untouched-since")) {
        (Some(tag), None) => Some(delete_tagged(flags, tag)),
        (None, Some(moment)) => Some(delete_untouched(flags, moment)),
        (Some(_), Some(_)) => Some(Err(Usage("delete takes --tag or --untouched-since, not both".to_string()).into())),
        (None, None) => None,
    }
}

pub(crate) fn delete_tagged(flags: &HashMap<String, String>, tag: &str) -> Result<Value> {
    let mut vault = Vault::open(vault_path())?;
    let tagged = carrying(&vault, tag, false);
    if tagged.is_empty() {
        return Err(Usage(format!("no live item carries the tag {tag}, so nothing was trashed")).into());
    }
    if !flag_set(flags, "yes") {
        return Ok(json!({"ok": true, "confirmed": false, "tag": tag, "would_trash": tagged}));
    }
    for id in &tagged {
        ensure_owner_mutation_allowed(&vault, id, "remove")?;
    }
    let mut grants = serde_json::Map::new();
    for id in &tagged {
        vault.delete_item(id)?;
        let naming = grants_naming(&vault, id);
        if !naming.is_empty() {
            grants.insert(id.clone(), json!(naming));
        }
    }
    crate::runtime::audit::append("items-trashed-by-tag", &json!({"tag": tag, "items": tagged}))?;
    Ok(json!({"ok": true, "confirmed": true, "tag": tag, "trashed": tagged, "grants_naming_them": grants}))
}

/// `delete --untouched-since <iso> [--yes]`: every live item no journal
/// entry has named since the moment — the secrets nothing reads or changes —
/// listed as `list --untouched-since` lists them, or with --yes trashed,
/// every one checked before any moves. The trash keeps them, so `restore`
/// brings back one a forgotten program still needed.
pub(crate) fn delete_untouched(flags: &HashMap<String, String>, moment: &str) -> Result<Value> {
    let listed = super::list::cmd_list(&HashMap::from([("untouched-since".to_string(), moment.to_string())]))?;
    let untouched: Vec<String> = listed
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    if untouched.is_empty() {
        return Err(Usage(format!("every live item has been named in the journal since {moment}, so nothing was trashed")).into());
    }
    if !flag_set(flags, "yes") {
        return Ok(json!({"ok": true, "confirmed": false, "untouched_since": moment, "would_trash": untouched}));
    }
    let mut vault = Vault::open(vault_path())?;
    for id in &untouched {
        ensure_owner_mutation_allowed(&vault, id, "remove")?;
    }
    let mut grants = serde_json::Map::new();
    for id in &untouched {
        vault.delete_item(id)?;
        let naming = grants_naming(&vault, id);
        if !naming.is_empty() {
            grants.insert(id.clone(), json!(naming));
        }
    }
    crate::runtime::audit::append("items-trashed-untouched", &json!({"untouched_since": moment, "items": untouched}))?;
    Ok(json!({"ok": true, "confirmed": true, "untouched_since": moment, "trashed": untouched, "grants_naming_them": grants}))
}

/// `restore --tag <tag> [--yes]`: the trashed items carrying the tag, listed,
/// or with --yes all put back in the live inventory, as restore puts one.
pub(crate) fn restore_tagged(flags: &HashMap<String, String>, tag: &str) -> Result<Value> {
    let mut vault = Vault::open(vault_path())?;
    let tagged = carrying(&vault, tag, true);
    if tagged.is_empty() {
        return Err(Usage(format!("no trashed item carries the tag {tag}, so nothing was restored")).into());
    }
    if !flag_set(flags, "yes") {
        return Ok(json!({"ok": true, "confirmed": false, "tag": tag, "would_restore": tagged}));
    }
    for id in &tagged {
        ensure_owner_mutation_allowed(&vault, id, "acquire")?;
    }
    for id in &tagged {
        vault.restore_item(id)?;
    }
    crate::runtime::audit::append("items-restored-by-tag", &json!({"tag": tag, "items": tagged}))?;
    Ok(json!({"ok": true, "confirmed": true, "tag": tag, "restored": tagged}))
}

/// The ids of the items carrying `tag`: the live ones, or with `trashed`
/// the ones in the trash. Every act on a tag's items reads them here.
pub(crate) fn carrying(vault: &Vault, tag: &str, trashed: bool) -> Vec<String> {
    vault
        .list(trashed)
        .iter()
        .filter(|item| (item.get("state").and_then(Value::as_str) == Some("trashed")) == trashed)
        .filter(|item| {
            item.get("tags")
                .and_then(Value::as_array)
                .is_some_and(|tags| tags.iter().any(|held| held.as_str() == Some(tag)))
        })
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
        .collect()
}
