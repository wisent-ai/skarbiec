// Reading an export file into rows this vault can write: which format the
// bytes are, and the canonical shape every provider is turned into.

use std::num::NonZeroUsize;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::core::schema;

use super::providers::{bitwarden, csv, onepassword};
use super::{ImportDocument, ImportRow};

/// The byte-order mark some exporters put before UTF-8 text.
const BYTE_ORDER_MARK: &str = "\u{feff}";

/// How a sealed export begins: what `export --encrypt-to` writes now, and the
/// armored OpenPGP message it wrote before.
const SEALED: [&str; 2] = [
    "-----BEGIN SKARBIEC SEALED-----",
    "-----BEGIN PGP MESSAGE-----",
];

/// The format the caller asked for; every other name is a CSV provider's.
enum Declared {
    Auto,
    Canonical,
    OnePassword,
    Bitwarden,
    Csv,
}

fn declared(format: &str) -> Declared {
    match format {
        "auto" => Declared::Auto,
        "canonical" => Declared::Canonical,
        "1password" => Declared::OnePassword,
        "bitwarden" => Declared::Bitwarden,
        _ => Declared::Csv,
    }
}

pub(super) fn parse(bytes: &[u8], format: &str) -> Result<ImportDocument> {
    let requested = declared(format);
    if bytes.starts_with(b"PK\x03\x04") {
        if !matches!(requested, Declared::Auto | Declared::OnePassword) {
            bail!(
                "only 1Password 1PUX archives are supported; export Bitwarden as unencrypted JSON"
            );
        }
        return onepassword::archive(bytes);
    }
    let bytes = match bytes.strip_prefix(BYTE_ORDER_MARK.as_bytes()) {
        Some(text) => text,
        None => bytes,
    };
    // A sealed export opens with this host's secret key, then is read as the
    // export it holds; a key this host lacks is the key file's refusal.
    if SEALED
        .iter()
        .any(|begin| bytes.starts_with(begin.as_bytes()))
    {
        let armored = std::str::from_utf8(bytes)
            .context("a sealed export is armored text, and this is not UTF-8")?;
        let opened = crate::core::crypto::decrypt(armored)
            .context("open the sealed export with this host's secret key")?;
        return parse(opened.as_bytes(), format);
    }
    let first = bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace());
    if matches!(first, Some(b'{' | b'[')) {
        let value: Value = serde_json::from_slice(bytes).context("invalid import JSON")?;
        return match requested {
            Declared::Canonical => canonical(value),
            Declared::OnePassword => onepassword::document(value),
            Declared::Bitwarden => bitwarden::document(value),
            Declared::Auto if value.is_array() => canonical(value),
            Declared::Auto if value.get("accounts").is_some() => onepassword::document(value),
            Declared::Auto if value.get("items").is_some() || value.get("encrypted").is_some() => {
                bitwarden::document(value)
            }
            Declared::Auto | Declared::Csv => {
                bail!("JSON is not a supported canonical, 1Password, or Bitwarden export")
            }
        };
    }
    if matches!(requested, Declared::Canonical) {
        bail!("canonical import requires a JSON array");
    }
    csv::document(bytes, format)
}

/// One row of a canonical export, exactly: any other property is refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalRow {
    id: String,
    payload: Value,
    #[serde(default)]
    recipients: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
}

pub(super) fn canonical(value: Value) -> Result<ImportDocument> {
    let listed = value
        .as_array()
        .context("canonical import requires a JSON array")?;
    let mut rows = Vec::with_capacity(listed.len());
    // Rows are numbered from the first, as the export lists them.
    for (number, row) in (NonZeroUsize::MIN.get()..).zip(listed) {
        let row = CanonicalRow::deserialize(row)
            .with_context(|| format!("import row {number} is not a canonical row"))?;
        if row.id.trim().is_empty() {
            bail!("import row {number} requires a nonempty id");
        }
        let kind = row
            .payload
            .get("kind")
            .and_then(Value::as_str)
            .context("canonical import payload requires kind")?;
        schema::validate_payload(&row.payload, kind)?;
        rows.push(ImportRow {
            title: row.id.clone(),
            id: row.id,
            payload: row.payload,
            recipients: row.recipients,
            tags: row.tags,
            source_key: None,
        });
    }
    Ok(ImportDocument {
        format: "canonical",
        rows,
    })
}
