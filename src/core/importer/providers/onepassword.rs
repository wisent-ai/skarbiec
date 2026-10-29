use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::{json, Map, Value};
use std::io::{Cursor, Read};
use zip::ZipArchive;

use super::super::{
    card_fields, login_fields, source_row, text, ImportDocument, StatedCard, NOT_STATED,
};

/// The 1PUX export version this reader understands.
/// <https://support.1password.com/1pux-format/>
const EXPORT_VERSION: u64 = 3;
/// The `categoryUuid` 1Password gives a login.
/// <https://support.1password.com/1pux-format/>
const LOGIN_CATEGORY: &str = "001";
/// The `categoryUuid` 1Password gives a secure note.
/// <https://support.1password.com/1pux-format/>
const SECURE_NOTE_CATEGORY: &str = "003";
/// Where a 1PUX archive keeps documents, attachments and custom icons.
const FILES_PREFIX: &str = "files/";
/// What separates a stored file's 1Password id from its own name.
const FILE_NAME_SEPARATOR: &str = "___";

pub(in crate::core::importer) fn archive(bytes: &[u8]) -> Result<ImportDocument> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).context("invalid 1Password 1PUX archive")?;
    let data =
        read_member(&mut archive, "export.data").context("1PUX archive requires export.data")?;
    let attributes: Value =
        serde_json::from_slice(&read_member(&mut archive, "export.attributes")?)
            .context("invalid 1PUX export.attributes")?;
    match attributes.get("version").and_then(Value::as_u64) {
        Some(EXPORT_VERSION) => {}
        Some(version) => bail!(
            "1PUX export version {version} is not read here; export version {EXPORT_VERSION} from 1Password"
        ),
        None => bail!(
            "1PUX export.attributes states no version; export version {EXPORT_VERSION} from 1Password"
        ),
    }
    let value: Value = serde_json::from_slice(&data).context("invalid 1PUX export.data")?;
    let mut account_ids: Vec<String> = value
        .get("accounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|account| {
            Ok(text(&account["attrs"], "uuid")
                .context("1Password account")?
                .to_string())
        })
        .collect::<Result<_>>()?;
    account_ids.sort();
    let mut document = document(value)?;
    // Keep documents, attachments and custom icons as encrypted bundle items.
    // No archive path is ever extracted to the filesystem.
    let names: Vec<String> = archive.file_names().map(str::to_string).collect();
    for name in names {
        let mut member = archive
            .by_name(&name)
            .with_context(|| format!("read 1PUX archive member {name}"))?;
        if member.is_dir() || name == "export.data" || name == "export.attributes" {
            continue;
        }
        let Some(stored) = name.strip_prefix(FILES_PREFIX) else {
            bail!("unsupported 1PUX archive member {name}; no items were written");
        };
        let mut content = Vec::new();
        member.read_to_end(&mut content)?;
        let file_name = match stored.rsplit_once(FILE_NAME_SEPARATOR) {
            Some((_, file_name)) => file_name,
            None => stored,
        };
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

pub(in crate::core::importer) fn read_member(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    name: &str,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    archive
        .by_name(name)
        .with_context(|| format!("1PUX archive has no {name}"))?
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The value of the login field whose `designation` is `designation`, or
/// nothing when the item has no such field.
fn designated<'a>(login: Option<&'a Vec<Value>>, designation: &str) -> Result<&'a str> {
    for field in login.into_iter().flatten() {
        if text(field, "designation")? == designation {
            return text(field, "value");
        }
    }
    Ok(NOT_STATED)
}

/// The first value of type `value_type` (`totp`, `creditCardNumber`, the
/// section field types the 1PUX format names) any of the item's sections
/// states, or nothing when none does.
/// <https://support.1password.com/1pux-format/>
fn first_stated<'a>(details: &'a Value, value_type: &str) -> Result<&'a str> {
    let fields = details
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
        });
    for field in fields {
        if let Some(value) = field.get("value") {
            let stated = text(value, value_type)?;
            if !stated.is_empty() {
                return Ok(stated);
            }
        }
    }
    Ok(NOT_STATED)
}

pub(in crate::core::importer) fn document(mut value: Value) -> Result<ImportDocument> {
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
                let at = format!("1Password item {item_id}");
                let overview = item
                    .get("overview")
                    .with_context(|| format!("{at} requires overview"))?;
                let details = item
                    .get("details")
                    .with_context(|| format!("{at} requires details"))?;
                let title = text(overview, "title")
                    .with_context(|| at.clone())?
                    .to_string();
                let notes = text(details, "notesPlain").with_context(|| at.clone())?;
                let state = text(&item, "state").with_context(|| at.clone())?;
                let mut context = Map::from_iter([
                    (
                        "url".into(),
                        json!(text(overview, "url").with_context(|| at.clone())?),
                    ),
                    ("notes".into(), json!(notes)),
                    (
                        "folder".into(),
                        json!(text(&vault_attrs, "name").with_context(|| at.clone())?),
                    ),
                    ("source_state".into(), json!(state)),
                ]);
                if let Some(urls) = overview.get("urls") {
                    context.insert("urls".into(), urls.clone());
                }
                let login = details.get("loginFields").and_then(Value::as_array);
                let category = text(&item, "categoryUuid").with_context(|| at.clone())?;
                let card_number =
                    first_stated(details, "creditCardNumber").with_context(|| at.clone())?;
                let (kind, fields) = if state == "archived" {
                    context.insert("import_warning".into(), json!("Archived source item retained as a bundle; its credentials were not activated."));
                    (
                        "bundle",
                        Map::from_iter([("source_record".into(), item.clone())]),
                    )
                } else if login.is_some() || category == LOGIN_CATEGORY {
                    (
                        "login",
                        login_fields(
                            designated(login, "username").with_context(|| at.clone())?,
                            designated(login, "password").with_context(|| at.clone())?,
                            first_stated(details, "totp").with_context(|| at.clone())?,
                            &mut context,
                        ),
                    )
                } else if category == SECURE_NOTE_CATEGORY {
                    ("note", Map::from_iter([("value".into(), json!(notes))]))
                } else if !card_number.is_empty() {
                    // The format names a credit card number's field type but
                    // not the template ids of a card's other fields, so the
                    // number is what is read; the rest stays in the source.
                    let card = StatedCard {
                        number: card_number,
                        cardholder: NOT_STATED,
                        month: NOT_STATED,
                        year: NOT_STATED,
                        security_code: NOT_STATED,
                        brand: NOT_STATED,
                    };
                    ("payment-card", card_fields(&card, &mut context))
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
    let id = text(value, "uuid").with_context(|| format!("1Password {kind}"))?;
    if id.is_empty() {
        bail!("1Password {kind} requires a nonempty uuid");
    }
    Ok(id)
}
