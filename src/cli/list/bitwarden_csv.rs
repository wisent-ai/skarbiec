// The CSV Bitwarden's "Bitwarden (csv)" import reads
// (https://bitwarden.com/help/condition-bitwarden-import/), so a vault's
// logins and notes move to Bitwarden — or to any manager that reads that
// format — with their sites, second-factor seeds and notes, and leaving
// Skarbiec never means retyping a vault.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use super::browser_csv::quote;
use crate::core::items::item_domains;
use crate::core::schema;

const HEADER: &str = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp";

/// One CSV document for `rows` (each an id and its decrypted payload). The
/// format holds logins and notes only, so any other kind is refused naming
/// the items, rather than left out of a file that would read as complete.
pub(crate) fn items(rows: &[(String, Value)]) -> Result<String> {
    let kind_of = |payload: &Value| {
        payload
            .get("kind")
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let others: Vec<&str> = rows
        .iter()
        .filter(|(_, payload)| !matches!(kind_of(payload).as_deref(), Some("login") | Some("note")))
        .map(|(id, _)| id.as_str())
        .collect();
    if !others.is_empty() {
        bail!(
            "--bitwarden-csv holds logins and notes only, and these items are another kind: {}; narrow with --kind login or --kind note",
            others.join(", ")
        );
    }
    let mut document = String::from(HEADER);
    document.push('\n');
    for (id, payload) in rows {
        let fields = schema::fields(payload)?;
        let text = |name: &str| -> Result<String> {
            match fields.get(name) {
                None => Ok(String::new()),
                Some(Value::String(value)) => Ok(value.clone()),
                Some(other) => bail!("{id}'s {name} is {other}, not text"),
            }
        };
        let context = payload.get("context");
        let name = match context.and_then(crate::core::items::display_name) {
            Some(name) => name.to_string(),
            None => id.clone(),
        };
        let notes = match context.and_then(crate::core::items::notes) {
            Some(notes) => notes.to_string(),
            None => String::new(),
        };
        let is_login = kind_of(payload).as_deref() == Some("login");
        let (kind, notes, uris, username, password, totp) = if is_login {
            let uris: Vec<String> = context
                .map(item_domains)
                .into_iter()
                .flatten()
                .map(|domain| format!("https://{domain}/"))
                .collect();
            (
                "login",
                notes,
                uris.join(","),
                text("username").with_context(|| format!("{id} cannot be exported"))?,
                text("password").with_context(|| format!("{id} cannot be exported"))?,
                text("totp_secret").with_context(|| format!("{id} cannot be exported"))?,
            )
        } else {
            // A note's text is its value; notes kept beside it follow it.
            let value = text("value").with_context(|| format!("{id} cannot be exported"))?;
            let body = if notes.is_empty() {
                value
            } else {
                format!("{value}\n\n{notes}")
            };
            (
                "note",
                body,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
        };
        let cells = [
            String::new(),
            String::new(),
            kind.to_string(),
            name,
            notes,
            String::new(),
            String::new(),
            uris,
            username,
            password,
            totp,
        ];
        let quoted: Vec<String> = cells.iter().map(|cell| quote(cell)).collect();
        document.push_str(&quoted.join(","));
        document.push('\n');
    }
    Ok(document)
}
