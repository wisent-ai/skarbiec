// Finding an item by what a person remembers about it: its display name,
// the username or email it signs in with, or a site it is for. `list
// --match` reads ids and tags only, because those sit in the cleartext
// envelope; these live inside the ciphertext, so each live item is opened.
// Secret fields are never compared and never printed: a search that matched
// a password would tell whoever reads the answer something about it.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::items::item_domains;
use crate::core::{schema, vault::Vault, vault_path};

/// The fields a person names an account by. Every other field is a secret
/// or a credential detail and is left alone.
const IDENTIFYING_FIELDS: &[&str] = &["username", "email", "phone", "api_user", "client_id"];

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "find" => find(flags, positionals).map(Some),
        _ => Ok(None),
    }
}

/// `skarbiec find <text> [--notes]`: every live item whose name, identifying
/// field or site contains the text, regardless of case, with where it
/// matched; `--notes` also looks in the notes an item carries, which the
/// owner wrote to be found by and which hold no credential field.
fn find(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let in_notes = crate::cli::args::flag_set(flags, "notes");
    let Some(asked) = positionals.first().filter(|text| !text.trim().is_empty()) else {
        return Err(crate::cli::args::Usage(
            "usage: find <text>; it is looked for in names, usernames, emails, phones and sites".to_string(),
        )
        .into());
    };
    let needle = asked.trim().to_lowercase();
    let vault = Vault::open(vault_path())?;
    let mut found = Vec::new();
    let mut unreadable = Vec::new();
    for entry in vault.list(false) {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        let payload = match vault.get_item(id) {
            Ok(payload) => payload,
            Err(error) => {
                unreadable.push(json!({"item": id, "error": format!("{error:#}")}));
                continue;
            }
        };
        let mut matched = Vec::new();
        let context = payload.get("context");
        if let Some(name) = context.and_then(crate::core::items::display_name) {
            if name.to_lowercase().contains(&needle) {
                matched.push("name".to_string());
            }
        }
        if in_notes
            && context
                .and_then(crate::core::items::notes)
                .is_some_and(|notes| notes.to_lowercase().contains(&needle))
        {
            matched.push("notes".to_string());
        }
        if let Some(context) = context {
            if item_domains(context).iter().any(|domain| domain.to_lowercase().contains(&needle)) {
                matched.push("sites".to_string());
            }
        }
        // A payload without a fields object is named with the reason, not
        // passed over: leaving it out would read as "nothing matched there".
        let fields = match schema::fields(&payload) {
            Ok(fields) => fields,
            Err(error) => {
                unreadable.push(json!({"item": id, "error": format!("{error:#}")}));
                continue;
            }
        };
        for field in IDENTIFYING_FIELDS {
            let held = fields.get(*field).and_then(Value::as_str);
            if held.is_some_and(|held| held.to_lowercase().contains(&needle)) {
                matched.push((*field).to_string());
            }
        }
        if !matched.is_empty() {
            found.push(json!({"item": id, "kind": entry.get("kind"), "matched": matched}));
        }
    }
    Ok(json!({"ok": true, "text": asked.trim(), "items": found, "unreadable": unreadable}))
}
