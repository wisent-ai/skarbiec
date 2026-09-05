use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::{json, Map, Value};
use std::io::{Cursor, Read};
use zip::ZipArchive;

use super::{login_fields, source_row, text, ImportDocument, MAX_IMPORT_BYTES};

pub(super) fn archive(bytes: &[u8]) -> Result<ImportDocument> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).context("invalid 1Password 1PUX archive")?;
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let member = archive
            .by_index(index)
            .context("read 1PUX archive member")?;
        total = total
            .checked_add(member.size())
            .context("1PUX archive size overflow")?;
        if total > MAX_IMPORT_BYTES {
            bail!("1PUX archive exceeds the 256 MiB uncompressed limit");
        }
    }
    let data =
        read_member(&mut archive, "export.data").context("1PUX archive requires export.data")?;
    let attributes: Value =
        serde_json::from_slice(&read_member(&mut archive, "export.attributes")?)
            .context("invalid 1PUX export.attributes")?;
    if attributes.get("version").and_then(Value::as_u64) != Some(3) {
        bail!("unsupported 1PUX export version; export version 3 from 1Password");
    }
    let value: Value = serde_json::from_slice(&data).context("invalid 1PUX export.data")?;
    let mut account_ids: Vec<String> = value
        .get("accounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|account| text(&account["attrs"], "uuid").to_string())
        .collect();
    account_ids.sort();
    let mut document = document(value)?;
    // Keep documents, attachments and custom icons as encrypted bundle items.
    // No archive path is ever extracted to the filesystem.
    for index in 0..archive.len() {
        let mut member = archive
            .by_index(index)
            .context("read 1PUX archive member")?;
        if member.is_dir() {
            continue;
        }
        let name = member.name().to_string();
        if name == "export.data" || name == "export.attributes" {
            continue;
        }
        if !name.starts_with("files/") {
            bail!("unsupported 1PUX archive member {name}; no items were written");
        }
        let mut content = Vec::new();
        member
            .by_ref()
            .take(MAX_IMPORT_BYTES + 1)
            .read_to_end(&mut content)?;
        if content.len() as u64 > MAX_IMPORT_BYTES {
            bail!("1PUX attachment exceeds the 256 MiB limit");
        }
        let file_name = name
            .rsplit_once("___")
            .map(|(_, name)| name)
            .unwrap_or_else(|| name.trim_start_matches("files/"));
        let fields = Map::from_iter([
            ("file_name".into(), json!(file_name)),
            (
                "content_base64".into(),
                Value::String(base64::engine::general_purpose::STANDARD.encode(content)),
            ),
        ]);
        let mut identity: Vec<&str> = account_ids.iter().map(String::as_str).collect();
        identity.push(&name);
        document.rows.push(source_row(
            "1password-file",
            &identity,
            file_name.to_string(),
            "bundle",
            fields,
            Map::from_iter([("source_path".into(), json!(name))]),
            json!({"path": name}),
        )?);
    }
    document.format = "1password-1pux";
    Ok(document)
}

fn read_member(archive: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    archive
        .by_name(name)
        .with_context(|| format!("1PUX archive has no {name}"))?
        .take(MAX_IMPORT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_IMPORT_BYTES {
        bail!("1PUX member exceeds the 256 MiB limit");
    }
    Ok(bytes)
}

pub(super) fn document(mut value: Value) -> Result<ImportDocument> {
    let accounts = value
        .get_mut("accounts")
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .context("1Password export requires an accounts array")?;
    let mut rows = Vec::new();
    for mut account in accounts {
        let account_attrs = account
            .get("attrs")
            .context("1Password account requires attrs")?
            .clone();
        let account_id = required_id(&account_attrs, "account")?;
        let vaults = account
            .get_mut("vaults")
            .and_then(Value::as_array_mut)
            .map(std::mem::take)
            .context("1Password account requires vaults")?;
        for mut vault in vaults {
            let vault_attrs = vault
                .get("attrs")
                .context("1Password vault requires attrs")?
                .clone();
            let vault_id = required_id(&vault_attrs, "vault")?;
            let items = vault
                .get_mut("items")
                .and_then(Value::as_array_mut)
                .map(std::mem::take)
                .context("1Password vault requires items")?;
            for item in items {
                let item_id = required_id(&item, "item")?.to_string();
                let overview = item
                    .get("overview")
                    .context("1Password item requires overview")?;
                let details = item
                    .get("details")
                    .context("1Password item requires details")?;
                let title = text(overview, "title").to_string();
                let mut context = Map::from_iter([
                    ("url".into(), json!(text(overview, "url"))),
                    ("notes".into(), json!(text(details, "notesPlain"))),
                    ("folder".into(), json!(text(&vault_attrs, "name"))),
                    ("source_state".into(), json!(text(&item, "state"))),
                ]);
                if let Some(urls) = overview.get("urls") {
                    context.insert("urls".into(), urls.clone());
                }
                let login = details.get("loginFields").and_then(Value::as_array);
                let field = |designation: &str| {
                    login
                        .into_iter()
                        .flatten()
                        .find(|field| text(field, "designation") == designation)
                        .map(|field| text(field, "value"))
                        .unwrap_or_default()
                };
                let totp = details
                    .get("sections")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .flat_map(|section| {
                        section
                            .get("fields")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                    })
                    .find_map(|field| {
                        field
                            .get("value")
                            .and_then(|value| value.get("totp"))
                            .and_then(Value::as_str)
                    })
                    .unwrap_or_default();
                let (kind, fields) = if text(&item, "state") == "archived" {
                    context.insert("import_warning".into(), json!("Archived source item retained as a bundle; its credentials were not activated."));
                    (
                        "bundle",
                        Map::from_iter([("source_record".into(), item.clone())]),
                    )
                } else if login.is_some() || text(&item, "categoryUuid") == "001" {
                    (
                        "login",
                        login_fields(field("username"), field("password"), totp, &mut context),
                    )
                } else if text(&item, "categoryUuid") == "003" {
                    (
                        "note",
                        Map::from_iter([("value".into(), json!(text(details, "notesPlain")))]),
                    )
                } else {
                    (
                        "bundle",
                        Map::from_iter([("source_record".into(), item.clone())]),
                    )
                };
                let original = Value::Object(Map::from_iter([
                    ("account".into(), account_attrs.clone()),
                    ("vault".into(), vault_attrs.clone()),
                    ("item".into(), item),
                ]));
                rows.push(source_row(
                    "1password",
                    &[account_id, vault_id, &item_id],
                    title,
                    kind,
                    fields,
                    context,
                    original,
                )?);
            }
        }
    }
    Ok(ImportDocument {
        format: "1password-json",
        rows,
    })
}

fn required_id<'a>(value: &'a Value, kind: &str) -> Result<&'a str> {
    let id = text(value, "uuid");
    if id.is_empty() {
        bail!("1Password {kind} requires a nonempty uuid");
    }
    Ok(id)
}
