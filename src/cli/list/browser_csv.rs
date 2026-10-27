// The password CSV Chrome, Edge, Firefox and Safari import: one header row
// naming name, url, username, password and note, then one row per login.
// It is how a vault hands its logins to a browser's own password manager,
// the reverse of `import --format browser-csv`.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::core::items::item_domains;
use crate::core::schema;

const HEADER: &str = "name,url,username,password,note";

/// One CSV document for `rows` (each an id and its decrypted payload). Every
/// row must be a login: a browser has no column for another kind's fields,
/// and leaving such an item out would read as exported when it was not.
pub(crate) fn logins(rows: &[(String, Value)]) -> Result<String> {
    let others: Vec<&str> = rows
        .iter()
        .filter(|(_, payload)| payload.get("kind").and_then(Value::as_str) != Some("login"))
        .map(|(id, _)| id.as_str())
        .collect();
    if !others.is_empty() {
        bail!(
            "--browser-csv holds logins only, and these items are another kind: {}; add --kind login",
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
        let name = context.and_then(crate::core::items::display_name).map(str::to_string);
        // A login's first site is the address the browser files it under;
        // one with no site is still a login, filed under no address.
        let url = match context.map(item_domains).as_deref().and_then(<[String]>::first) {
            Some(domain) => format!("https://{domain}/"),
            None => String::new(),
        };
        let username = text("username").with_context(|| format!("{id} cannot be exported"))?;
        let password = text("password").with_context(|| format!("{id} cannot be exported"))?;
        // The notes go in the browser's note column, where the import reads
        // them back from; a login without notes leaves it empty.
        let note = match context.and_then(crate::core::items::notes) {
            Some(text) => text.to_string(),
            None => String::new(),
        };
        let cells = [
            match name {
                Some(name) => name,
                None => id.clone(),
            },
            url,
            username,
            password,
            note,
        ];
        let quoted: Vec<String> = cells.iter().map(|cell| quote(cell)).collect();
        document.push_str(&quoted.join(","));
        document.push('\n');
    }
    Ok(document)
}

/// RFC 4180: every cell in double quotes, a quote inside doubled, so a comma,
/// a quote or a line break in a value never moves it to another column.
pub(super) fn quote(cell: &str) -> String {
    format!("\"{}\"", cell.replace('"', "\"\""))
}
