// Reading an export file into rows this vault can write: which format the
// bytes are, and the canonical shape every provider is turned into.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::core::schema;

use super::{bitwarden, csv, onepassword, ImportDocument, ImportRow};

pub(super) fn parse(bytes: &[u8], format: &str) -> Result<ImportDocument> {
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

pub(super) fn canonical(value: Value) -> Result<ImportDocument> {
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
