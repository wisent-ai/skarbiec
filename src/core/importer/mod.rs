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

/// The format an import reads when `--format` names none: detected from the
/// export itself, as `import --help` declares.
const DEFAULT_FORMAT: &str = "auto";
/// What an import does with an item the vault already holds when
/// `--conflict` names nothing: keeps the vault's, as `import --help` declares.
const DEFAULT_CONFLICT: &str = "keep";

pub fn run(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    if flags.get("help").is_some_and(|value| value == "true") {
        return Ok(json!({
            "command": "import",
            "usage": "skarbiec import <export-file> [--format FORMAT] [--conflict POLICY]",
            "formats": ["auto", "canonical", "1password", "bitwarden", "browser-csv"],
            "conflict_policies": ["keep", "replace", "error"],
            "default_format": DEFAULT_FORMAT,
            "default_conflict_policy": DEFAULT_CONFLICT,
        }));
    }
    let [path] = positionals else {
        return Err(crate::cli::args::Usage("usage: import <export-file> [--format auto|canonical|1password|bitwarden|browser-csv] [--conflict keep|replace|error]".to_string()).into());
    };
    let format = match flags.get("format") {
        Some(format) => format.as_str(),
        None => DEFAULT_FORMAT,
    };
    let conflict = match flags.get("conflict") {
        Some(conflict) => conflict.as_str(),
        None => DEFAULT_CONFLICT,
    };
    import_file(Path::new(path), format, conflict)
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
    let mut source =
        File::open(path).with_context(|| format!("read import file {}", path.display()))?;
    if !source.metadata()?.is_file() {
        bail!("import source must be a regular file");
    }
    // The export is the operator's own file: it is read whole, and every row
    // it holds is imported; no size or row count was ever decided for it.
    let mut bytes = Vec::new();
    source.read_to_end(&mut bytes)?;
    let document = parse(&bytes, format)?;
    if document.rows.is_empty() {
        bail!("import contains no items");
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
        .collect();
    let slug = slug.trim_matches('-');
    let label = if slug.is_empty() { "import" } else { slug };
    Ok(ImportRow {
        id: format!("{label}-{provider}-{digest}"),
        title,
        payload,
        recipients: Vec::new(),
        tags: vec!["imported".into(), provider.into()],
        source_key: Some(format!("{provider}:{digest}")),
    })
}

/// What an export's absent or null text field reads as. Exporters leave out
/// a field that holds nothing, and the source identity of an item imported
/// before this reader existed hashes the empty text for it, so a re-import
/// still finds that item.
pub(super) const NOT_STATED: &str = "";

/// The text `value` states under `key`: itself when it is text, nothing when
/// the export leaves the field out or nulls it. A field holding anything
/// else (a number, an object, a list) is refused naming the field and the
/// kind of value it holds, never the value, which may be a secret; reading it
/// as empty would import the item without the value the export carried.
pub(super) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    let held = match value.get(key) {
        Some(Value::String(text)) => return Ok(text),
        Some(Value::Null) | None => return Ok(NOT_STATED),
        Some(Value::Bool(_)) => "a boolean",
        Some(Value::Number(_)) => "a number",
        Some(Value::Array(_)) => "a list",
        Some(Value::Object(_)) => "an object",
    };
    bail!("the export's {key} holds {held}, not text; nothing was imported")
}

/// A login's fields. A TOTP the export states is activated through the one
/// otpauth reader `totp set` uses, so an address with another algorithm, digit
/// count or period is kept in `extensions.import.source` and the warning names
/// which of them it broke.
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
        match crate::runtime::totp::given_seed(totp) {
            Ok(seed) => {
                fields.insert("totp_secret".into(), Value::String(seed));
            }
            Err(cause) => {
                context.insert("import_warning".into(), json!(format!(
                    "The original authenticator value was retained in extensions.import.source but was not activated: {cause:#}"
                )));
            }
        }
    }
    fields
}
