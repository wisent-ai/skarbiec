//! User-owned exports enter the same typed vault writer through CLI and GUI.
//! Parsing and encryption finish before the single generation-checked save.

mod parse;
mod providers;
mod write;

use parse::parse;
use write::apply;

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::schema;

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
