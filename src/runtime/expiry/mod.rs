// When an item stops being good: the day a card, a passport, a licence key or
// password the provider forces to change runs out. `expiry set <id> --on
// <iso>` records it, `expiry list [--before <iso>]` names what runs out
// first, `expiry tokens` reads the end stored JSON Web Tokens carry
// themselves (`tokenexpiry`), and `review` reads it beside certificates. The date is the vault's
// own metadata in the `item_expiry` section, beside share_until, so listing
// it opens no item.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::{OrUsage, Usage};
use crate::core::{clock, vault::Vault, vault_path};

/// The vault section: item id -> the moment the item runs out.
const SECTION: &str = "item_expiry";
const USAGE: &str = "usage: expiry set <id> --on <iso8601> | expiry set --tag <tag> --on <iso8601> | expiry clear <id> | expiry clear --tag <tag> | expiry list [--before <iso8601>] | expiry tokens [--before <iso8601>]";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "expiry" {
        return Ok(None);
    }
    let answer = match positionals {
        [verb, rest @ ..] if verb == "tokens" => crate::runtime::tokenexpiry::report(flags, rest)?,
        [verb, id] if verb == "set" => set(id, flags.get("on").or_usage(USAGE)?)?,
        [verb] if verb == "set" => set_tagged(flags.get("tag").or_usage(USAGE)?, flags.get("on").or_usage(USAGE)?)?,
        [verb, id] if verb == "clear" => clear(id)?,
        [verb] if verb == "clear" => clear_tagged(flags.get("tag").or_usage(USAGE)?)?,
        [verb] if verb == "list" => list(flags.get("before"))?,
        _ => return Err(Usage(USAGE.to_string()).into()),
    };
    Ok(Some(answer))
}

fn stamp(flag: &str, value: &str) -> Result<()> {
    if clock::is_iso(value) {
        return Ok(());
    }
    Err(Usage(format!("--{flag} {value} is not a UTC time of the form {}", clock::now_iso())).into())
}

/// Record when one live item runs out; a date already past is allowed, since
/// recording a lapse is how it gets seen.
pub fn set(id: &str, on: &str) -> Result<Value> {
    stamp("on", on)?;
    let mut vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "set the expiry of")?;
    vault.get_item(id)?;
    record(&mut vault, &[id.to_string()], on)?;
    vault.save()?;
    crate::runtime::audit::append("expiry-set", &json!({"item": id, "on": on}))?;
    Ok(json!({"ok": true, "item": id, "expires_at": on}))
}

/// `expiry set --tag <tag> --on <iso>`: the same date on every live item one
/// tag carries — a contractor's set, a project's — checked before any is
/// written, so a refused one leaves every date as it was.
pub fn set_tagged(tag: &str, on: &str) -> Result<Value> {
    stamp("on", on)?;
    let mut vault = Vault::open(vault_path())?;
    let tagged = crate::cli::bulk::carrying(&vault, tag, false);
    if tagged.is_empty() {
        return Err(Usage(format!("no live item carries the tag {tag}, so no expiry was recorded")).into());
    }
    for id in &tagged {
        crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "set the expiry of")?;
    }
    record(&mut vault, &tagged, on)?;
    vault.save()?;
    crate::runtime::audit::append("expiry-set-by-tag", &json!({"tag": tag, "items": tagged, "on": on}))?;
    Ok(json!({"ok": true, "tag": tag, "items": tagged, "expires_at": on}))
}

/// Write `on` as the date of every id into the vault's section, unsaved.
fn record(vault: &mut Vault, ids: &[String], on: &str) -> Result<()> {
    let section = vault
        .doc_mut()
        .as_object_mut()
        .context("the vault document is not an object")?
        .entry(SECTION.to_string())
        .or_insert_with(|| json!({}));
    let Value::Object(section) = section else {
        anyhow::bail!("the vault's {SECTION} section is not an object");
    };
    for id in ids {
        section.insert(id.clone(), json!(on));
    }
    Ok(())
}

/// Forget one item's date; one that records none answers cleared false.
pub fn clear(id: &str) -> Result<Value> {
    let mut vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "clear the expiry of")?;
    let removed = vault
        .doc_mut()
        .get_mut(SECTION)
        .and_then(Value::as_object_mut)
        .is_some_and(|section| section.remove(id).is_some());
    if removed {
        vault.save()?;
        crate::runtime::audit::append("expiry-cleared", &json!({"item": id}))?;
    }
    Ok(json!({"ok": true, "item": id, "cleared": removed}))
}

/// `expiry clear --tag <tag>`: forget the date of every live item the tag
/// carries, checked before any is forgotten; `cleared` names the ones that
/// recorded a date, and nothing is written when none did.
pub fn clear_tagged(tag: &str) -> Result<Value> {
    let mut vault = Vault::open(vault_path())?;
    let tagged = crate::cli::bulk::carrying(&vault, tag, false);
    if tagged.is_empty() {
        return Err(Usage(format!("no live item carries the tag {tag}, so no expiry was cleared")).into());
    }
    for id in &tagged {
        crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "clear the expiry of")?;
    }
    let cleared: Vec<String> = match vault.doc_mut().get_mut(SECTION).and_then(Value::as_object_mut) {
        Some(section) => tagged.iter().filter(|id| section.remove(id.as_str()).is_some()).cloned().collect(),
        None => Vec::new(),
    };
    if !cleared.is_empty() {
        vault.save()?;
        crate::runtime::audit::append("expiry-cleared-by-tag", &json!({"tag": tag, "items": cleared}))?;
    }
    Ok(json!({"ok": true, "tag": tag, "cleared": cleared}))
}

/// Every recorded date, soonest first, or only the ones before a moment;
/// each says whether it has passed and whether its item is still live.
pub fn list(before: Option<&String>) -> Result<Value> {
    if let Some(before) = before {
        stamp("before", before)?;
    }
    let vault = Vault::open(vault_path())?;
    let now = clock::now_iso();
    let live: Vec<String> = vault
        .list(false)
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let mut rows: Vec<(&str, &str)> = vault
        .doc()
        .get(SECTION)
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(id, on)| on.as_str().map(|on| (id.as_str(), on)))
        .filter(|(_, on)| before.is_none_or(|before| *on < before.as_str()))
        .collect();
    rows.sort_by(|left, right| left.1.cmp(right.1));
    let rows: Vec<Value> = rows
        .into_iter()
        .map(|(id, on)| {
            json!({
                "item": id,
                "expires_at": on,
                "expired": on <= now.as_str(),
                "live": live.iter().any(|known| known == id),
            })
        })
        .collect();
    Ok(json!(rows))
}

/// Carry a date to an item's new id after a rename; the caller saves.
pub fn follow_rename(vault: &mut Vault, from: &str, to: &str) -> bool {
    let Some(section) = vault.doc_mut().get_mut(SECTION).and_then(Value::as_object_mut) else {
        return false;
    };
    match section.remove(from) {
        Some(on) => {
            section.insert(to.to_string(), on);
            true
        }
        None => false,
    }
}

/// Drop a purged item's date, which nothing could ever act on again; the
/// caller saves. True when there was one.
pub fn forget(vault: &mut Vault, id: &str) -> bool {
    vault
        .doc_mut()
        .get_mut(SECTION)
        .and_then(Value::as_object_mut)
        .is_some_and(|section| section.remove(id).is_some())
}
