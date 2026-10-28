use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

use super::super::{login_fields, source_row, ImportDocument, NOT_STATED};

pub(in crate::core::importer) fn document(bytes: &[u8], requested: &str) -> Result<ImportDocument> {
    let mut reader = ::csv::ReaderBuilder::new().from_reader(bytes);
    let original_headers = reader
        .headers()
        .context("invalid import CSV header")?
        .clone();
    let headers: Vec<String> = original_headers
        .iter()
        .map(|header| header.trim().to_ascii_lowercase().replace([' ', '-'], "_"))
        .collect();
    let mut unique = HashSet::new();
    if headers
        .iter()
        .any(|header| header.is_empty() || !unique.insert(header))
    {
        bail!("import CSV contains an empty or duplicate header");
    }
    let has = |name: &str| headers.iter().any(|header| header == name);
    let detected = Export::DETECTION_ORDER
        .iter()
        .copied()
        .find(|export| export.headers_present(&has))
        .context("CSV does not have supported 1Password, Bitwarden, or browser export headers")?;
    let format = if requested == "auto" {
        detected
    } else {
        Export::DETECTION_ORDER
            .iter()
            .copied()
            .find(|export| export.name() == requested)
            .context("CSV requires the 1Password, Bitwarden, or browser-csv format")?
    };
    // A 1Password export is accepted whenever it has its title column; the
    // other two must be the format their headers were detected as.
    let accepted = format == detected || (format == Export::OnePassword && has("title"));
    if !accepted {
        bail!("CSV headers do not match the selected import format");
    }
    let provider = format.provider();
    let mut rows = Vec::new();
    for record in reader.records() {
        // The reader's error names the record and line it could not read.
        let record = record.context("invalid CSV record")?;
        if record.iter().all(str::is_empty) {
            continue;
        }
        let line = match record.position() {
            Some(position) => format!("on line {}", position.line()),
            None => "at a position the CSV reader did not record".to_string(),
        };
        // A column this export format does not carry reads as not stated,
        // as an exporter's absent field does: saved source identities hash
        // the empty text for it, so a re-import still finds their items.
        let get = |names: &[&str]| -> &str {
            let cell = names.iter().find_map(|name| {
                headers
                    .iter()
                    .position(|header| header == name)
                    .and_then(|index| record.get(index))
            });
            match cell {
                Some(cell) => cell,
                None => NOT_STATED,
            }
        };
        let title = get(&["title", "name"]);
        let url = get(&["website", "url", "login_uri"]);
        let username = get(&["username", "login_username"]);
        let password = get(&["password", "login_password"]);
        let totp = get(&["one_time_password", "otpauth", "login_totp"]);
        let notes = get(&["notes", "note"]);
        let folder = get(&["folder", "collections", "vault"]);
        let source = Value::Object(
            original_headers
                .iter()
                .zip(record.iter())
                .map(|(key, value)| (key.to_string(), json!(value)))
                .collect(),
        );
        let archived = match get(&["archived", "archived_status"])
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "0" | "false" | "no" => false,
            "1" | "true" | "yes" => true,
            _ => bail!("CSV record {line} has an unsupported archived value"),
        };
        let source_type = get(&["type"]);
        let mut context = Map::from_iter([
            ("url".into(), json!(url)),
            ("notes".into(), json!(notes)),
            ("folder".into(), json!(folder)),
        ]);
        let (kind, fields) = if archived {
            context.insert("import_warning".into(), json!("Archived source item retained as a bundle; its credentials were not activated."));
            (
                "bundle",
                Map::from_iter([("source_record".into(), source.clone())]),
            )
        } else if source_type == "note" {
            ("note", Map::from_iter([("value".into(), json!(notes))]))
        } else if source_type.is_empty() || source_type == "login" {
            (
                "login",
                login_fields(username, password, totp, &mut context),
            )
        } else {
            (
                "bundle",
                Map::from_iter([("source_record".into(), source.clone())]),
            )
        };
        let id = get(&["id", "uuid"]);
        let identity = if id.is_empty() {
            vec![title, url, username, folder, source_type]
        } else {
            vec![id]
        };
        rows.push(source_row(
            provider,
            &identity,
            title.to_string(),
            kind,
            fields,
            context,
            source,
        )?);
    }
    Ok(ImportDocument {
        format: provider,
        rows,
    })
}

/// A CSV export format, recognised by the header columns its exporter writes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Export {
    Bitwarden,
    OnePassword,
    Browser,
}

impl Export {
    /// Bitwarden's columns are the most specific, then 1Password's, and a
    /// browser export is what remains.
    const DETECTION_ORDER: &'static [Export] =
        &[Export::Bitwarden, Export::OnePassword, Export::Browser];

    /// The name `import --format` takes.
    fn name(self) -> &'static str {
        match self {
            Export::Bitwarden => "bitwarden",
            Export::OnePassword => "1password",
            Export::Browser => "browser-csv",
        }
    }

    /// The source an imported row records.
    fn provider(self) -> &'static str {
        match self {
            Export::Bitwarden => "bitwarden-csv",
            Export::OnePassword => "1password-csv",
            Export::Browser => "browser-csv",
        }
    }

    fn headers_present(self, has: &impl Fn(&str) -> bool) -> bool {
        match self {
            Export::Bitwarden => {
                has("type") && has("name") && has("login_username") && has("login_password")
            }
            Export::OnePassword => {
                has("title") && has("website") && has("username") && has("password")
            }
            Export::Browser => {
                (has("name") || has("title")) && has("url") && has("username") && has("password")
            }
        }
    }
}
