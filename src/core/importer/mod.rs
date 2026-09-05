//! User-owned exports enter the same typed vault writer through CLI and GUI.
//! Parsing and encryption finish before the single generation-checked save.

mod bitwarden;
mod csv;
mod onepassword;

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::schema;
use super::vault::{ItemWrite, Vault};

pub(super) const MAX_IMPORT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_IMPORT_ITEMS: usize = 100_000;

pub(super) struct ImportRow {
    id: String,
    payload: Value,
    recipients: Vec<String>,
    tags: Vec<String>,
    source_key: Option<String>,
    title: String,
}

pub(super) struct ImportDocument {
    format: &'static str,
    rows: Vec<ImportRow>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Conflict {
    Keep,
    Replace,
    Error,
}

pub fn run(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    if flags.get("help").is_some_and(|value| value == "true") {
        return Ok(json!({
            "command": "import",
            "usage": "skarbiec import <export-file> [--format FORMAT] [--conflict POLICY]",
            "formats": ["auto", "canonical", "1password", "bitwarden", "browser-csv"],
            "conflict_policies": ["keep", "replace", "error"],
            "default_conflict_policy": "keep",
            "max_input_bytes": MAX_IMPORT_BYTES,
            "max_items": MAX_IMPORT_ITEMS,
        }));
    }
    if positionals.len() != 1 {
        bail!("usage: import <export-file> [--format auto|canonical|1password|bitwarden|browser-csv] [--conflict keep|replace|error]");
    }
    import_file(
        Path::new(&positionals[0]),
        flags.get("format").map(String::as_str).unwrap_or("auto"),
        flags.get("conflict").map(String::as_str).unwrap_or("keep"),
    )
}

pub fn import_file(path: &Path, format: &str, conflict: &str) -> Result<Value> {
    let conflict = match conflict {
        "keep" => Conflict::Keep,
        "replace" => Conflict::Replace,
        "error" => Conflict::Error,
        _ => bail!("import conflict policy must be keep, replace, or error"),
    };
    if !["auto", "canonical", "1password", "bitwarden", "browser-csv"].contains(&format) {
        bail!("import format must be auto, canonical, 1password, bitwarden, or browser-csv");
    }
    let source =
        File::open(path).with_context(|| format!("read import file {}", path.display()))?;
    if !source.metadata()?.is_file() {
        bail!("import source must be a regular file");
    }
    let mut bytes = Vec::new();
    source.take(MAX_IMPORT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_IMPORT_BYTES {
        bail!("import exceeds the 256 MiB input limit");
    }
    let document = parse(&bytes, format)?;
    if document.rows.is_empty() {
        bail!("import contains no items");
    }
    if document.rows.len() > MAX_IMPORT_ITEMS {
        bail!("import exceeds the 100000 item limit");
    }
    apply(document, conflict)
}

fn parse(bytes: &[u8], format: &str) -> Result<ImportDocument> {
    if bytes.starts_with(b"PK\x03\x04") {
        if !["auto", "1password"].contains(&format) {
            bail!(
                "only 1Password 1PUX archives are supported; export Bitwarden as unencrypted JSON"
            );
        }
        return onepassword::archive(bytes);
    }
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let first = bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace());
    if matches!(first, Some(b'{' | b'[')) {
        let value: Value = serde_json::from_slice(bytes).context("invalid import JSON")?;
        return match format {
            "canonical" => canonical(value),
            "1password" => onepassword::document(value),
            "bitwarden" => bitwarden::document(value),
            "auto" if value.is_array() => canonical(value),
            "auto" if value.get("accounts").is_some() => onepassword::document(value),
            "auto" if value.get("items").is_some() || value.get("encrypted").is_some() => {
                bitwarden::document(value)
            }
            _ => bail!("JSON is not a supported canonical, 1Password, or Bitwarden export"),
        };
    }
    if format == "canonical" {
        bail!("canonical import requires a JSON array");
    }
    csv::document(bytes, format)
}

fn canonical(value: Value) -> Result<ImportDocument> {
    let mut rows = Vec::new();
    for (index, row) in value
        .as_array()
        .context("canonical import requires a JSON array")?
        .iter()
        .enumerate()
    {
        let object = row
            .as_object()
            .with_context(|| format!("import row {} must be an object", index + 1))?;
        if object
            .keys()
            .any(|key| !["id", "payload", "recipients", "tags"].contains(&key.as_str()))
        {
            bail!("import row {} contains an unsupported property", index + 1);
        }
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
            .with_context(|| format!("import row {} requires a nonempty id", index + 1))?;
        let payload = row
            .get("payload")
            .context("canonical import row requires payload")?
            .clone();
        let kind = payload
            .get("kind")
            .and_then(Value::as_str)
            .context("canonical import payload requires kind")?;
        schema::validate_payload(&payload, kind)?;
        let strings = |key: &str| -> Result<Vec<String>> {
            let Some(value) = row.get(key) else {
                return Ok(Vec::new());
            };
            value
                .as_array()
                .with_context(|| format!("canonical import {key} must be an array"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .with_context(|| format!("canonical import {key} entries must be strings"))
                })
                .collect()
        };
        rows.push(ImportRow {
            id: id.to_string(),
            title: id.to_string(),
            payload,
            recipients: strings("recipients")?,
            tags: strings("tags")?,
            source_key: None,
        });
    }
    Ok(ImportDocument {
        format: "canonical",
        rows,
    })
}

fn apply(mut document: ImportDocument, conflict: Conflict) -> Result<Value> {
    let mut vault = Vault::open(super::vault_path())?;
    let mut source_ids = HashMap::new();
    if let Some(items) = vault.doc().get("items").and_then(Value::as_object) {
        for (id, entry) in items {
            if let Some(source) = entry.get("import_source").and_then(Value::as_str) {
                if source_ids
                    .insert(source.to_string(), id.to_string())
                    .is_some()
                {
                    bail!(
                        "vault contains duplicate import source identities; no items were written"
                    );
                }
            }
        }
    }
    let mut seen = HashSet::with_capacity(document.rows.len());
    let mut selected = Vec::new();
    let mut results = Vec::with_capacity(document.rows.len());
    let (mut imported, mut updated, mut unchanged, mut conflicts) = (0, 0, 0, 0);
    for (index, row) in document.rows.iter_mut().enumerate() {
        if let Some(source) = &row.source_key {
            if let Some(id) = source_ids.get(source) {
                row.id = id.clone();
            }
        }
        if !seen.insert(row.id.clone()) {
            bail!(
                "duplicate source item in import: {}; no items were written",
                row.id
            );
        }
        let kind = row
            .payload
            .get("kind")
            .and_then(Value::as_str)
            .context("import payload has no kind")?;
        schema::validate_payload(&row.payload, kind)?;
        if row.tags.iter().any(|tag| tag == "managed:weles") {
            bail!("{} uses the reserved managed:weles tag", row.id);
        }
        for uid in &row.recipients {
            if vault.recipient_fpr(uid).is_none() {
                bail!("{} names an unknown recipient: {uid}", row.id);
            }
        }
        let existing = vault
            .doc()
            .get("items")
            .and_then(|items| items.get(&row.id));
        if let (Some(source), Some(existing)) = (&row.source_key, existing) {
            if existing.get("import_source").and_then(Value::as_str) != Some(source) {
                bail!(
                    "{} is occupied by another source; no items were written",
                    row.id
                );
            }
            row.recipients = vault.item_recipient_uids(&row.id);
            row.tags = existing
                .get("tags")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
        }
        let tags: Vec<Value> = row.tags.iter().cloned().map(Value::String).collect();
        let carried = existing
            .and_then(|item| item.get("tags"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        schema::ensure_registered_tags(carried, &tags)?;
        let status = if let Some(existing) = existing {
            vault.ensure_owner_controlled(&row.id)?;
            if crate::credential::lifecycle_owned_item(&vault, &row.id)
                || super::inbox::managed_by_weles(&vault, &row.id)
            {
                bail!(
                    "{} is managed by a credential lifecycle and cannot be imported",
                    row.id
                );
            }
            let active = existing.get("state").and_then(Value::as_str) == Some("active");
            let same = active
                && vault.get_item(&row.id)? == row.payload
                && carried == tags.as_slice()
                && vault.item_recipient_uids(&row.id) == row.recipients;
            if same {
                unchanged += 1;
                "unchanged"
            } else if conflict == Conflict::Keep {
                conflicts += 1;
                "kept_existing"
            } else if conflict == Conflict::Error {
                bail!(
                    "{} conflicts with an existing item; no items were written",
                    row.id
                );
            } else {
                updated += 1;
                selected.push(index);
                "updated"
            }
        } else {
            imported += 1;
            selected.push(index);
            "imported"
        };
        results.push(json!({
            "id": row.id, "title": row.title, "kind": kind, "status": status,
            "warning": row.payload.get("context").and_then(|context| context.get("import_warning")),
        }));
    }
    let writes: Vec<ItemWrite<'_>> = selected
        .iter()
        .map(|index| {
            let row = &document.rows[*index];
            ItemWrite {
                id: &row.id,
                kind: row.payload["kind"].as_str().expect("validated kind"),
                payload: &row.payload,
                recipients: &row.recipients,
                tags: &row.tags,
                import_source: row.source_key.as_deref(),
            }
        })
        .collect();
    vault.set_items_atomic(&writes)?;
    Ok(json!({
        "ok": true, "format": document.format, "total": results.len(),
        "vault": vault.path,
        "imported": imported, "updated": updated, "unchanged": unchanged,
        "conflicts": conflicts, "items": results,
    }))
}

pub(super) fn source_row(
    provider: &'static str,
    identity: &[&str],
    title: String,
    kind: &str,
    fields: Map<String, Value>,
    mut context: Map<String, Value>,
    original: Value,
) -> Result<ImportRow> {
    if identity.is_empty() {
        bail!("{provider} item has no source identity");
    }
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(identity)?));
    context.insert("display_name".into(), json!(title));
    let mut payload = schema::payload(kind, fields, context)?;
    payload["extensions"] = Value::Object(Map::from_iter([(
        "import".into(),
        Value::Object(Map::from_iter([
            ("provider".into(), json!(provider)),
            ("identity".into(), serde_json::to_value(identity)?),
            ("source".into(), original),
        ])),
    )]));
    let slug: String = title
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(40)
        .collect();
    let slug = slug.trim_matches('-');
    let label = if slug.is_empty() { "import" } else { slug };
    Ok(ImportRow {
        id: format!("{label}-{provider}-{}", &digest[..24]),
        title,
        payload,
        recipients: Vec::new(),
        tags: vec!["imported".into(), provider.into()],
        source_key: Some(format!("{provider}:{digest}")),
    })
}

pub(super) fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

pub(super) fn login_fields(
    username: &str,
    password: &str,
    totp: &str,
    context: &mut Map<String, Value>,
) -> Map<String, Value> {
    let mut fields = Map::from_iter([
        ("username".into(), json!(username)),
        ("password".into(), json!(password)),
    ]);
    if !totp.trim().is_empty() {
        if let Some(seed) = native_totp_seed(totp) {
            fields.insert("totp_secret".into(), Value::String(seed));
        } else {
            context.insert("import_warning".into(), json!(
                "The original authenticator value was retained in extensions.import.source but was not activated: Skarbiec requires a Base32 seed with SHA1, six digits, and a 30-second period."
            ));
        }
    }
    fields
}

fn native_totp_seed(value: &str) -> Option<String> {
    let value = value.trim();
    let seed = if value.starts_with("otpauth://") {
        let query = value.strip_prefix("otpauth://totp/")?.split_once('?')?.1;
        let mut parameters = HashMap::new();
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            if parameters.insert(key, value).is_some() {
                return None;
            }
        }
        if parameters
            .get("algorithm")
            .is_some_and(|value| !value.eq_ignore_ascii_case("SHA1"))
            || parameters
                .get("digits")
                .is_some_and(|value| value.parse::<u32>() != Ok(6))
            || parameters
                .get("period")
                .is_some_and(|value| value.parse::<u32>() != Ok(30))
        {
            return None;
        }
        parameters.get("secret")?.to_string()
    } else {
        value.to_string()
    };
    let seed: String = seed
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .map(|character| character.to_ascii_uppercase())
        .collect();
    crate::runtime::totp::base32_seed_shape(&seed).then_some(seed)
}
