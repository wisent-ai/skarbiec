use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

use super::{login_fields, source_row, ImportDocument};

pub(super) fn document(bytes: &[u8], requested: &str) -> Result<ImportDocument> {
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
    let detected = if has("type") && has("name") && has("login_username") && has("login_password") {
        "bitwarden"
    } else if has("title") && has("website") && has("username") && has("password") {
        "1password"
    } else if (has("name") || has("title")) && has("url") && has("username") && has("password") {
        "browser-csv"
    } else {
        bail!("CSV does not have supported 1Password, Bitwarden, or browser export headers");
    };
    let format = if requested == "auto" {
        detected
    } else {
        requested
    };
    if (format == "bitwarden" && detected != "bitwarden")
        || (format == "browser-csv" && detected != "browser-csv")
        || (format == "1password" && !has("title"))
    {
        bail!("CSV headers do not match the selected import format");
    }
    let provider = match format {
        "1password" => "1password-csv",
        "bitwarden" => "bitwarden-csv",
        "browser-csv" => "browser-csv",
        _ => bail!("CSV requires the 1Password, Bitwarden, or browser-csv format"),
    };
    let mut rows = Vec::new();
    for (index, record) in reader.records().enumerate() {
        let record = record.with_context(|| format!("invalid CSV record {}", index + 2))?;
        if record.iter().all(str::is_empty) {
            continue;
        }
        let get = |names: &[&str]| -> &str {
            names
                .iter()
                .find_map(|name| {
                    headers
                        .iter()
                        .position(|header| header == name)
                        .and_then(|index| record.get(index))
                })
                .unwrap_or_default()
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
            _ => bail!("CSV record {} has an unsupported archived value", index + 2),
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
