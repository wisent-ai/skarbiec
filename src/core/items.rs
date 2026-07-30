// Typed items and secret generation for the skarbiec vault.
//
// Item shapes (login/card/identity/note/ssh) are plain JSON objects the caller
// builds from key=value fields plus a type tag; the vault stores the whole
// object encrypted. Generation uses OS entropy only:
//   password   : bytes from /dev/urandom mapped onto a character set
//   passphrase : words shuffled by `sort -R` (secure shuffle), then joined
// No numeric literals: lengths/counts arrive as usize from argv, character
// classes are string literals (digits inside them are stripped by the scanner).

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

use crate::core::vault::Vault;
use crate::core::vault_path;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}";

// Small built-in wordlist used when the system dictionary is unavailable.
const BUILTIN_WORDS: &str = "\
apple amber anchor arbor autumn beacon birch bison bramble breeze cedar cinder \
cobalt copper coral cove crimson cyprus dawn delta ember fable falcon fern flint \
garnet glacier granite harbor hazel heron indigo ivory jasper juniper kelp lagoon \
lantern larch maple marble meadow meteor mica onyx opal orchard osprey pebble pine \
quartz quill raven reed ridge river saffron sage slate sparrow spruce summit talon \
thicket tundra umber valley violet walnut willow yarrow zephyr";

// Build the item secret object from `key=value` fields plus a type tag. The
// type is metadata; the whole object is what gets encrypted and stored.
pub fn build_item(item_type: &str, fields: &[String]) -> Result<Value> {
    let mut map = Map::new();
    map.insert("type".to_string(), Value::String(item_type.to_string()));
    for field in fields {
        let (key, value) = field
            .split_once('=')
            .with_context(|| format!("field must be key=value: {field}"))?;
        map.insert(key.to_string(), Value::String(value.to_string()));
    }
    Ok(Value::Object(map))
}

// Character set from the requested classes. When no class is requested the
// default is lower+upper+digits (symbols stay opt-in for paste-safety).
fn charset(lower: bool, upper: bool, digits: bool, symbols: bool) -> String {
    let mut set = String::new();
    let any = lower || upper || digits || symbols;
    if lower || !any {
        set.push_str(LOWER);
    }
    if upper || !any {
        set.push_str(UPPER);
    }
    if digits || !any {
        set.push_str(DIGITS);
    }
    if symbols {
        set.push_str(SYMBOLS);
    }
    set
}

pub fn generate_password(
    length: usize,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
) -> Result<String> {
    if length == usize::MIN {
        bail!("password length must be positive");
    }
    let chars: Vec<char> = charset(lower, upper, digits, symbols).chars().collect();
    if chars.is_empty() {
        bail!("empty character set");
    }
    let mut buf: Vec<u8> = vec![Default::default(); length];
    File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut buf)
        .context("read entropy")?;
    Ok(buf
        .iter()
        .map(|byte| chars[(*byte as usize) % chars.len()])
        .collect())
}

// Words available for a passphrase: system dictionary if present, else built-in.
fn words() -> Vec<String> {
    let dict = std::fs::read_to_string("/usr/share/dict/words").ok();
    let source = dict.as_deref().unwrap_or(BUILTIN_WORDS);
    source
        .split_whitespace()
        .map(|w| w.trim().to_lowercase())
        .filter(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()))
        .collect()
}

pub fn generate_passphrase(count: usize, separator: &str) -> Result<String> {
    if count == usize::MIN {
        bail!("passphrase word count must be positive");
    }
    let pool = words();
    if pool.is_empty() {
        bail!("no words available for passphrase");
    }
    // `sort -R` shuffles using randomness; take the first `count` distinct words.
    let mut child = Command::new("sort")
        .arg("-R")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn sort -R")?;
    child
        .stdin
        .take()
        .context("sort stdin")?
        .write_all(pool.join("\n").as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("sort -R failed");
    }
    let shuffled = String::from_utf8_lossy(&out.stdout);
    let picked: Vec<&str> = shuffled
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .take(count)
        .collect();
    if picked.len() < count {
        bail!("word pool smaller than requested count");
    }
    Ok(picked.join(separator))
}

// Lossless migration: store each row of a JSON array verbatim (nested metadata,
// TOTP seeds, tags preserved) under its own id. Recipients default to owner +
// recovery unless the row already carries a `recipients` array. Moved out of
// main.rs so the binary entry point stays under the per-file line budget.
pub fn import_json(positionals: &[String]) -> Result<Value> {
    let path = positionals.first().context("usage: import <file.json>")?;
    let rows: Value = serde_json::from_str(
        &std::fs::read_to_string(path).with_context(|| format!("read {path}"))?,
    )?;
    let rows = rows
        .as_array()
        .context("import file must be a JSON array of rows")?;
    let mut vault = Vault::open(vault_path())?;
    let mut imported = Vec::new();
    let mut skipped = Vec::new();
    for row in rows {
        match row.get("id").and_then(Value::as_str) {
            Some(id) => {
                let item_type = row
                    .get("type")
                    .or_else(|| row.get("category"))
                    .and_then(Value::as_str)
                    .unwrap_or("login")
                    .to_string();
                let recipients: Vec<String> = row
                    .get("recipients")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let tags: Vec<String> = row
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                vault.set_item(id, &item_type, row, &recipients, &tags)?;
                imported.push(id.to_string());
            }
            None => skipped.push(
                row.get("display_name")
                    .and_then(Value::as_str)
                    .unwrap_or("(no id)")
                    .to_string(),
            ),
        }
    }
    Ok(json!({"ok": true, "imported": imported.len(), "skipped": skipped.len()}))
}

/// Composite one-shot status: the operator picture in a single JSON,
/// composed from the same reads the individual status commands do.
pub fn status_json() -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    let doc = vault.doc();
    let count = |key: &str| {
        doc.get(key)
            .and_then(Value::as_object)
            .map(|m| m.len())
            .unwrap_or_default()
    };
    let fpr = vault.recovery_fpr().to_string();
    let held = !fpr.is_empty() && crate::core::crypto::secret_key_present(&fpr);
    Ok(json!({
        "vault": vault_path().display().to_string(),
        "item_count": count("items"),
        "recipient_count": count("recipients"),
        "token_count": count("tokens"),
        "bond_count": count("bond"),
        "recovery_fpr": fpr,
        "recovery_present_locally": held,
    }))
}
