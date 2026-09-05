use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use super::{login_fields, source_row, text, ImportDocument};

pub(super) fn document(mut value: Value) -> Result<ImportDocument> {
    if value
        .get("encrypted")
        .is_some_and(|encrypted| encrypted != &Value::Bool(false))
    {
        bail!(
            "Bitwarden export is encrypted; export an unencrypted JSON file and import it locally"
        );
    }
    let items = value
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .context("Bitwarden export requires an items array")?;
    let folders = index_metadata(&value, "folders")?;
    let collections = index_metadata(&value, "collections")?;
    let mut rows = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        if !item.is_object() {
            bail!("Bitwarden item {} must be an object", index + 1);
        }
        let id = text(&item, "id").to_string();
        let title = item
            .get("name")
            .and_then(Value::as_str)
            .with_context(|| format!("Bitwarden item {} requires name", index + 1))?
            .to_string();
        let kind_number = item
            .get("type")
            .and_then(Value::as_u64)
            .with_context(|| format!("Bitwarden item {} requires a numeric type", index + 1))?;
        let folder = folders
            .get(text(&item, "folderId"))
            .copied()
            .cloned()
            .unwrap_or(Value::Null);
        let collection_ids: Vec<&str> = match item.get("collectionIds") {
            Some(Value::Array(ids)) => ids
                .iter()
                .map(|id| {
                    id.as_str()
                        .context("Bitwarden collectionIds must contain strings")
                })
                .collect::<Result<_>>()?,
            Some(Value::String(id)) => vec![id],
            Some(Value::Null) | None => Vec::new(),
            _ => bail!("Bitwarden collectionIds must be an array, a string, or null"),
        };
        let item_collections: Vec<Value> = collection_ids
            .iter()
            .filter_map(|id| collections.get(id).copied())
            .cloned()
            .collect();
        let mut context = Map::from_iter([
            ("notes".into(), json!(text(&item, "notes"))),
            ("folder".into(), json!(text(&folder, "name"))),
        ]);
        let login = item.get("login").unwrap_or(&Value::Null);
        let username = text(login, "username");
        let url = login
            .get("uris")
            .and_then(Value::as_array)
            .and_then(|uris| uris.first())
            .map(|uri| text(uri, "uri"))
            .unwrap_or_default();
        context.insert("url".into(), json!(url));
        if let Some(uris) = login.get("uris") {
            context.insert("urls".into(), uris.clone());
        }
        let (kind, fields) = match kind_number {
            1 => (
                "login",
                login_fields(
                    username,
                    text(login, "password"),
                    text(login, "totp"),
                    &mut context,
                ),
            ),
            2 => (
                "note",
                Map::from_iter([("value".into(), json!(text(&item, "notes")))]),
            ),
            _ => (
                "bundle",
                Map::from_iter([("source_record".into(), item.clone())]),
            ),
        };
        // UUIDs survive renames and repeated exports. Minimal custom exports
        // without UUIDs use their non-secret identity, never their password.
        let identity = if id.is_empty() {
            vec![
                "custom".to_string(),
                kind_number.to_string(),
                title.clone(),
                username.to_string(),
                url.to_string(),
                text(&folder, "name").to_string(),
            ]
        } else {
            vec![text(&item, "organizationId").to_string(), id]
        };
        let identity_refs: Vec<&str> = identity.iter().map(String::as_str).collect();
        let original = Value::Object(Map::from_iter([
            ("item".into(), item),
            ("folder".into(), folder),
            ("collections".into(), json!(item_collections)),
        ]));
        rows.push(source_row(
            "bitwarden",
            &identity_refs,
            title,
            kind,
            fields,
            context,
            original,
        )?);
    }
    Ok(ImportDocument {
        format: "bitwarden-json",
        rows,
    })
}

fn index_metadata<'a>(value: &'a Value, key: &str) -> Result<HashMap<&'a str, &'a Value>> {
    let Some(records) = value.get(key) else {
        return Ok(HashMap::new());
    };
    let records = records
        .as_array()
        .with_context(|| format!("Bitwarden {key} must be an array"))?;
    let mut index = HashMap::with_capacity(records.len());
    for record in records {
        let id = text(record, "id");
        if id.is_empty() || index.insert(id, record).is_some() {
            bail!("Bitwarden {key} contains an empty or duplicate id");
        }
    }
    Ok(index)
}
