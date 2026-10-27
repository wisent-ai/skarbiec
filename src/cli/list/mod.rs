// `skarbiec list`: the metadata of the vault's items, narrowed by the filters
// `export` and the operator API share. It decrypts nothing.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;
use crate::core::vault_path;

use super::args::{flag_set, Usage};

pub(crate) mod bitwarden_csv;
pub(crate) mod browser_csv;
mod untouched;

/// `list [--all | --trashed] [--kind <kind>] [--tag <tag>]
/// [--updated-before <iso8601>] [--match <text>] [--shared-with <uid>]
/// [--untouched-since <iso8601>] [--pinned]`: item
/// metadata, narrowed to one kind, to items carrying one tag, to items whose
/// last write is older than a moment (the values nobody has rotated since),
/// to ids or tags containing a text regardless of case, to the items one
/// recipient can open, and with `--trashed` to the trash alone. A kind this
/// binary does not know is refused naming the kinds the vault does hold,
/// because an empty answer would read as "no such items" when the question
/// itself was wrong. `--untouched-since` keeps the items the audit journal
/// has not named since a moment: the secrets nothing uses. `--pinned` keeps
/// the items `pin add` put at the front.
pub(crate) fn cmd_list(flags: &HashMap<String, String>) -> Result<Value> {
    let trashed_only = flag_set(flags, "trashed");
    if trashed_only && flag_set(flags, "all") {
        return Err(Usage(
            "--trashed lists the trash alone and --all lists everything; name one".to_string(),
        )
        .into());
    }
    let vault = Vault::open(vault_path())?;
    // An unregistered uid can open nothing, so an empty answer would read as
    // "shared with nobody"; the question is refused naming who is registered.
    if let Some(uid) = flags.get("shared-with") {
        if vault.recipient_fpr(uid).is_none() {
            let registered: Vec<&str> = vault
                .doc()
                .get("recipients")
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|recipients| recipients.keys().map(String::as_str))
                .collect();
            return Err(Usage(format!(
                "--shared-with {uid} is not a registered recipient; the registered recipients are: {}",
                registered.join(", ")
            ))
            .into());
        }
    }
    let items: Vec<Value> = vault
        .list(trashed_only || flag_set(flags, "all"))
        .into_iter()
        .filter(|item| !trashed_only || item.get("deleted") == Some(&Value::Bool(true)))
        .collect();
    let kind = flags.get("kind");
    if let Some(kind) = kind {
        if !crate::core::schema::supported_kind(kind) {
            let mut held: Vec<&str> = items
                .iter()
                .filter_map(|item| item.get("kind").and_then(Value::as_str))
                .collect();
            held.sort_unstable();
            held.dedup();
            return Err(Usage(format!(
                "--kind {kind} is not an item kind; this vault holds: {}",
                held.join(", ")
            ))
            .into());
        }
    }
    let updated_before = flags.get("updated-before");
    if let Some(before) = updated_before {
        if !crate::core::clock::is_iso(before) {
            return Err(Usage(format!(
                "--updated-before {before} is not a UTC time of the form {}",
                crate::core::clock::now_iso()
            ))
            .into());
        }
    }
    let needle = match flags.get("match") {
        Some(text) if text.trim().is_empty() => {
            return Err(Usage("--match needs text to look for in item ids and tags".to_string()).into())
        }
        Some(text) => Some(text.to_lowercase()),
        None => None,
    };
    let tag = flags.get("tag");
    // `--shared-with <uid>` keeps the items whose envelope lists that
    // recipient: what one person can open, in the same listing.
    let shared_with = flags.get("shared-with");
    let touched = untouched::named_since(flags.get("untouched-since"))?;
    let pinned = flag_set(flags, "pinned").then(|| crate::runtime::pins::pinned(&vault));
    let matching: Vec<Value> = items
        .into_iter()
        .filter(|item| match kind {
            Some(kind) => item.get("kind").and_then(Value::as_str) == Some(kind.as_str()),
            None => true,
        })
        .filter(|item| match tag {
            Some(tag) => tags(item).any(|held| held == tag.as_str()),
            None => true,
        })
        // An item that records no write time is older than any moment asked
        // about: nothing says it was written since.
        .filter(|item| match updated_before {
            Some(before) => match item.get("updated_at").and_then(Value::as_str) {
                Some(at) => at < before.as_str(),
                None => true,
            },
            None => true,
        })
        .filter(|item| match &needle {
            Some(needle) => {
                let id = item.get("id").and_then(Value::as_str);
                id.is_some_and(|id| id.to_lowercase().contains(needle.as_str()))
                    || tags(item).any(|held| held.to_lowercase().contains(needle.as_str()))
            }
            None => true,
        })
        .filter(|item| match shared_with {
            Some(uid) => item
                .get("recipients")
                .and_then(Value::as_array)
                .is_some_and(|readers| readers.iter().any(|reader| reader.as_str() == Some(uid.as_str()))),
            None => true,
        })
        .filter(|item| match &touched {
            Some(touched) => item.get("id").and_then(Value::as_str).is_some_and(|id| !touched.contains(id)),
            None => true,
        })
        .filter(|item| match &pinned {
            Some(pinned) => item.get("id").and_then(Value::as_str).is_some_and(|id| pinned.iter().any(|held| held == id)),
            None => true,
        })
        .collect();
    Ok(json!(matching))
}

/// The tags one listed item carries.
fn tags(item: &Value) -> impl Iterator<Item = &str> {
    item.get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}
