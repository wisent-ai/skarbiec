// The free text an item carries beside its fields: security answers, the
// support PIN, which phone the account was opened on. It lives in the
// encrypted payload's context as `notes`, so it is read and written with the
// value's own protection, and changing it is a new revision like any change.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;

use crate::core::items::{notes, NOTES};
use crate::core::{vault::Vault, vault_path};

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "notes" {
        return Ok(None);
    }
    let [id, ..] = positionals else {
        return Err(crate::cli::args::Usage(
            "usage: notes <id> [--set]  (--set reads the new notes on stdin; empty input removes them)".to_string(),
        )
        .into());
    };
    if crate::cli::args::flag_set(flags, "set") {
        let mut given = String::new();
        std::io::stdin()
            .read_to_string(&mut given)
            .context("the notes could not be read from standard input")?;
        return set(id, &given).map(Some);
    }
    read(id).map(Some)
}

/// The notes one item carries, or null when it carries none.
fn read(id: &str) -> Result<Value> {
    let payload = Vault::open(vault_path())?.get_item(id)?;
    let notes = payload.get("context").and_then(notes);
    Ok(json!({"ok": true, "item": id, "notes": notes}))
}

/// Replace the notes with `given`; text that is only whitespace removes
/// them. Called by the command line and by `POST /v1/operator/items/notes/set`.
pub fn set(id: &str, given: &str) -> Result<Value> {
    set_context_text(
        id,
        NOTES,
        given.trim_end_matches('\n'),
        "change the notes of",
        "notes-set",
    )
}

/// Write one text member of an item's encrypted context as a new revision —
/// its notes, the site's password rules — or remove it when `given` is only
/// whitespace. `doing` names the change in a refusal and `operation` in the
/// journal; the value itself is never journalled.
pub fn set_context_text(
    id: &str,
    key: &str,
    given: &str,
    doing: &str,
    operation: &str,
) -> Result<Value> {
    let mut vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, doing)?;
    let mut payload = vault.get_item(id)?;
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .with_context(|| format!("{id} records no kind"))?
        .to_string();
    let context = payload
        .as_object_mut()
        .with_context(|| format!("{id}'s payload is not an object"))?
        .entry("context".to_string())
        .or_insert_with(|| json!({}));
    let Value::Object(context) = context else {
        bail!("{id}'s context is not an object");
    };
    let removed = given.trim().is_empty();
    if removed {
        context.remove(key);
    } else {
        context.insert(key.to_string(), json!(given));
    }
    let recipients = vault.item_recipient_uids(id)?;
    let tags = {
        let entry = vault
            .doc()
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        crate::core::vault::entry_texts(id, entry, "tags")?
    };
    vault.set_item(id, &kind, &payload, &recipients, &tags)?;
    let revision = vault.item_revision(id)?;
    crate::runtime::audit::append(
        operation,
        &json!({"item": id, "removed": removed, "revision": revision}),
    )?;
    Ok(json!({"ok": true, "item": id, "removed": removed, "revision": revision}))
}
