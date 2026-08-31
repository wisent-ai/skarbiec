// Canonical item construction and secret generation for the Skarbiec vault.
//
// Every newly written item uses `skarbiec.item.v2`: one validated kind, a
// logical fields object, and encrypted context. Generation uses OS entropy.
// No numeric literals: lengths/counts arrive as usize from argv, character
// classes are string literals (digits inside them are stripped by the scanner).

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::{migrate, schema, vault::Vault, vault_path};

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

// Build a canonical payload from `key=value` logical fields. Context-rich and
// profile-based bundle items use `set-json` instead.
pub fn build_item(item_kind: &str, fields: &[String]) -> Result<Value> {
    let mut map = Map::new();
    for field in fields {
        let (key, value) = field
            .split_once('=')
            .with_context(|| format!("field must be key=value: {field}"))?;
        map.insert(key.to_string(), Value::String(value.to_string()));
    }
    schema::payload(item_kind, map, Map::new())
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

// Import canonical rows shaped as `{id, payload, recipients?, tags?}`. Legacy
// arrays must first pass through the explicit `migrate-v2` command.
pub fn import_json(positionals: &[String]) -> Result<Value> {
    let path = positionals.first().context("usage: import <file.json>")?;
    let rows: Value = serde_json::from_str(
        &std::fs::read_to_string(path).with_context(|| format!("read {path}"))?,
    )?;
    let rows = rows
        .as_array()
        .context("import file must be a JSON array of canonical rows")?;
    let mut vault = Vault::open(vault_path())?;
    let mut imported = Vec::new();
    let mut skipped = Vec::new();
    for row in rows {
        match row.get("id").and_then(Value::as_str) {
            Some(id) => {
                if crate::credential::lifecycle_owned_item(&vault, id) {
                    bail!("{id} is managed by the credential lifecycle and cannot be imported");
                }
                if crate::core::inbox::managed_by_weles(&vault, id) {
                    bail!(
                        "{id} is managed by Weles; import cannot overwrite an externally managed credential"
                    );
                }
                let payload = row
                    .get("payload")
                    .context("canonical import row requires payload")?;
                let item_kind = payload
                    .get("kind")
                    .and_then(Value::as_str)
                    .context("canonical import payload requires kind")?;
                crate::core::schema::validate_payload(payload, item_kind)?;
                let recipients: Vec<String> = row
                    .get("recipients")
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let tags: Vec<String> = row
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                if tags.iter().any(|tag| tag == "managed:weles") {
                    bail!("{id} uses the reserved managed:weles tag");
                }
                vault.set_item(id, item_kind, payload, &recipients, &tags)?;
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

pub fn migrate_v2(flags: &std::collections::HashMap<String, String>) -> Result<Value> {
    let source = vault_path();
    let snapshot = flags.get("snapshot").map_or_else(
        || -> Result<PathBuf> {
            let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            Ok(PathBuf::from(format!(
                "{}.pre-v2.{epoch}",
                source.display()
            )))
        },
        |path| Ok(PathBuf::from(path)),
    )?;
    if snapshot.exists() {
        bail!("migration snapshot already exists: {}", snapshot.display());
    }
    let mut input = File::open(&source)
        .with_context(|| format!("open vault snapshot source {}", source.display()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(u32::from_str_radix("600", "8".parse()?)?)
        .open(&snapshot)
        .with_context(|| format!("create migration snapshot {}", snapshot.display()))?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    let mut vault = Vault::open(source)?;
    let report = migrate::migrate(&mut vault)?;
    Ok(json!({
        "ok": true,
        "snapshot": snapshot.display().to_string(),
        "items": report.items,
        "revisions": report.revisions,
        "grants": report.grants,
    }))
}

/// Copy every live item from one vault file into another.
///
/// This is the supported way to merge a private vault — for example one held
/// by a private Weles instance — into the fleet vault, replacing ad-hoc
/// scripting. Each source item is decrypted locally and re-encrypted to the
/// target vault's own recipients: the target owner and its recovery key, never
/// the source's recipient list, whose uids mean nothing in the target. The
/// item keeps its id, kind, schema, context, fields and tags; the target
/// writer stamps `management` as owner-controlled by the target owner, the
/// same as any other owner write.
///
/// An id already present in the target is skipped unless `--force`; even with
/// `--force` an item owned by the credential lifecycle or managed by Weles is
/// refused, and the target writer itself refuses to displace an item whose
/// recorded controller is not the owner. The report names id, kind and sorted
/// field names only — never a field value. The first unreadable or unwritable
/// item stops the run with the id in the error.
pub fn migrate_vault(flags: &std::collections::HashMap<String, String>) -> Result<Value> {
    let from = flags
        .get("from")
        .context("usage: migrate --from <vault-file> --to <vault-file> [--force]")?;
    let to = flags
        .get("to")
        .context("usage: migrate --from <vault-file> --to <vault-file> [--force]")?;
    if from == to {
        bail!("--from and --to must be different vault files");
    }
    let force = flags.get("force").map(|v| v == "true").unwrap_or(false);
    let source =
        Vault::open(PathBuf::from(from)).with_context(|| format!("open source vault {from}"))?;
    let mut target =
        Vault::open(PathBuf::from(to)).with_context(|| format!("open target vault {to}"))?;
    let mut migrated = Vec::new();
    let mut skipped = Vec::new();
    for entry in source.list(false) {
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .context("source vault lists an item without an id")?;
        let exists_in_target = target
            .doc()
            .get("items")
            .and_then(Value::as_object)
            .is_some_and(|items| items.contains_key(id));
        if exists_in_target && !force {
            skipped.push(id.to_string());
            continue;
        }
        if crate::credential::lifecycle_owned_item(&source, id)
            || crate::credential::lifecycle_owned_item(&target, id)
        {
            bail!("{id} is managed by the credential lifecycle and cannot be migrated");
        }
        if crate::core::inbox::managed_by_weles(&target, id) {
            bail!(
                "{id} is managed by Weles in the target vault; migrate cannot overwrite an externally managed credential"
            );
        }
        let payload = source
            .get_item(id)
            .with_context(|| format!("read source item {id}"))?;
        let item_kind = entry
            .get("kind")
            .and_then(Value::as_str)
            .or_else(|| payload.get("kind").and_then(Value::as_str))
            .with_context(|| format!("source item {id} has no kind"))?;
        let tags: Vec<String> = entry
            .get("tags")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        target
            .set_item(id, item_kind, &payload, &[], &tags)
            .with_context(|| format!("write item {id} into target vault"))?;
        let mut field_names: Vec<String> = payload
            .get("fields")
            .and_then(Value::as_object)
            .map(|fields| fields.keys().cloned().collect())
            .unwrap_or_default();
        field_names.sort();
        migrated.push(json!({"id": id, "kind": item_kind, "fields": field_names}));
    }
    Ok(json!({
        "ok": true,
        "from": from,
        "to": to,
        "force": force,
        "migrated": migrated,
        "skipped": skipped,
    }))
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
