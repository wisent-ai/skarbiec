// `copy <id> <new-id> [--without <field,...>]`: a new item from an existing
// one — the staging account made like production, the second card of the
// same bank — with the same kind, tags and recipients. `--without` leaves
// fields out, so a copy can start with the shape and not the secret. The
// original is untouched; the copy has its own history from its first write.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;
use crate::core::vault_path;

use super::args::Usage;

const USAGE: &str = "usage: copy <id> <new-id> [--without <field,...>]";

pub(crate) fn copy_value(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let [from, to] = positionals else {
        return Err(Usage(USAGE.to_string()).into());
    };
    if from == to {
        return Err(Usage(format!("{from} and the copy have the same id; name a new one")).into());
    }
    let vault = Vault::open(vault_path())?;
    if vault.doc().get("items").and_then(|items| items.get(to.as_str())).is_some() {
        bail!("{to} already exists, live or trashed; copy creates an item and never replaces one");
    }
    let mut payload = vault.get_item(from)?;
    let left_out: Vec<String> = match flags.get("without") {
        Some(listed) => listed
            .split(',')
            .map(str::trim)
            .filter(|field| !field.is_empty())
            .map(str::to_string)
            .collect(),
        None => Vec::new(),
    };
    if !left_out.is_empty() {
        let fields = payload
            .get_mut("fields")
            .and_then(Value::as_object_mut)
            .with_context(|| format!("{from} holds no fields object, so --without has nothing to leave out"))?;
        for field in &left_out {
            if fields.remove(field).is_none() {
                return Err(Usage(format!("{from} has no field {field} to leave out")).into());
            }
        }
    }
    let entry = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(from.as_str()))
        .with_context(|| format!("no item: {from}"))?;
    let tags = crate::core::vault::entry_texts(from, entry, "tags")?;
    let recipients = vault.item_recipient_uids(from)?;
    let mut write = HashMap::new();
    if !tags.is_empty() {
        write.insert("tags".to_string(), tags.join(","));
    }
    if !recipients.is_empty() {
        write.insert("recipients".to_string(), recipients.join(","));
    }
    if let Some(kind) = entry.get("kind").and_then(Value::as_str) {
        write.insert("type".to_string(), kind.to_string());
    }
    let written = super::items::create_value(&write, to, &payload.to_string(), "copy")?;
    crate::runtime::audit::append("item-copied", &json!({"from": from, "to": to, "without": left_out}))?;
    // A copied login is offered by autofill at once, as a new login is.
    let autofill = match entry.get("kind").and_then(Value::as_str) {
        Some("login") => match crate::browser::cover_login(to) {
            Ok(answer) => answer,
            Err(error) => json!({"covered": false, "error": format!("{error:#}")}),
        },
        _ => Value::Null,
    };
    Ok(json!({
        "ok": true,
        "from": from,
        "to": to,
        "without": left_out,
        "created": written.get("created"),
        "autofill": autofill,
    }))
}
