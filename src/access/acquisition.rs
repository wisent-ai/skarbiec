// Short-lived, field-bound, single-use acquisition bearers. Bootstrap grants
// may request an acquisition but can never use the direct item read path.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::access::tokens;
use crate::core::{crypto, vault::Vault, vault_path};

struct StateLock {
    path: PathBuf,
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

fn private_file_mode() -> Result<u32> {
    u32::from_str_radix("600", "8".parse()?).context("private file mode")
}

fn private_dir_mode() -> Result<u32> {
    u32::from_str_radix("700", "8".parse()?).context("private directory mode")
}

fn unsafe_mode_bits() -> Result<u32> {
    u32::from_str_radix("077", "8".parse()?).context("unsafe mode bits")
}

fn effective_uid() -> Result<u32> {
    let output = Command::new("id").arg("-u").output().context("read effective uid")?;
    if !output.status.success() {
        bail!("could not determine effective uid");
    }
    String::from_utf8(output.stdout)?.trim().parse().context("parse effective uid")
}

fn state_path() -> PathBuf {
    if let Ok(path) = std::env::var("SKARBIEC_ACQUISITION_FILE") {
        return PathBuf::from(path);
    }
    let vault = vault_path();
    let name = vault
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.acquisitions.json"))
        .unwrap_or_else(|| "skarbiec.vault.acquisitions.json".to_string());
    vault.with_file_name(name)
}

fn lock_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.lock"))
        .unwrap_or_else(|| "skarbiec.vault.acquisitions.lock".to_string());
    path.with_file_name(name)
}

fn acquire_lock(path: &Path) -> Result<StateLock> {
    let lock = lock_path(path);
    let attempts: usize = "500".parse()?;
    let pause = Duration::from_millis("10".parse()?);
    for _ in std::iter::repeat(()).take(attempts) {
        match DirBuilder::new().mode(private_dir_mode()?).create(&lock) {
            Ok(()) => return Ok(StateLock { path: lock }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => thread::sleep(pause),
            Err(error) => return Err(error).context("create acquisition state lock"),
        }
    }
    bail!("acquisition state is locked")
}

fn validate_owned_regular(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.uid() != effective_uid()? {
        bail!("acquisition state must be an owner-controlled regular file");
    }
    if metadata.mode() & unsafe_mode_bits()? != u32::MIN {
        bail!("acquisition state permissions must not grant group or other access");
    }
    Ok(())
}

fn load_state(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(json!({"version": "v1", "tokens": {}}));
    }
    validate_owned_regular(path)?;
    let state: Value = serde_json::from_str(&fs::read_to_string(path)?)
        .context("parse acquisition state")?;
    if state.get("version").and_then(Value::as_str) != Some("v1")
        || !state.get("tokens").is_some_and(Value::is_object)
    {
        bail!("invalid acquisition state document");
    }
    Ok(state)
}

fn save_state(path: &Path, state: &Value) -> Result<()> {
    let parent = path.parent().context("acquisition state has no parent")?;
    fs::create_dir_all(parent)?;
    let suffix = format!("{}.{}", std::process::id(), now_epoch()?);
    let temp = path.with_extension(format!("tmp.{suffix}"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(private_file_mode()?)
        .open(&temp)
        .context("create acquisition state temporary file")?;
    let result = (|| -> Result<()> {
        file.write_all(serde_json::to_string_pretty(state)?.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(private_file_mode()?))?;
        fs::rename(&temp, path)?;
        let _ = File::open(parent).and_then(|directory| directory.sync_all());
        validate_owned_regular(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn now_epoch() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn ttl_seconds() -> Result<u64> {
    let ttl: u64 = std::env::var("SKARBIEC_ACQUISITION_TTL_SECONDS")
        .unwrap_or_else(|_| "30".to_string())
        .parse()
        .context("SKARBIEC_ACQUISITION_TTL_SECONDS must be an integer")?;
    let maximum: u64 = "300".parse()?;
    if ttl == u64::MIN || ttl > maximum {
        bail!("SKARBIEC_ACQUISITION_TTL_SECONDS must be between one and 300")
    }
    Ok(ttl)
}

fn exact_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_target(vault: &Vault, item: &str, field: &str) -> Result<()> {
    if !exact_name(item) || !exact_name(field) {
        bail!("item and field must be exact names without wildcards or separators");
    }
    let value = vault.get_item(item)?;
    let object = value.as_object().context("acquisition item must be a JSON object")?;
    if !object.contains_key(field) {
        bail!("acquisition field does not exist on item");
    }
    Ok(())
}

fn purge_expired(state: &mut Value, now: u64) -> Result<()> {
    let tokens = state
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .context("acquisition tokens section")?;
    tokens.retain(|_, record| {
        record
            .get("expires_at")
            .and_then(Value::as_u64)
            .is_some_and(|expiry| expiry > now)
    });
    Ok(())
}

pub struct IssuedAcquisition {
    pub token: String,
    pub expires_at: u64,
}

pub fn issue(
    consumer: &str,
    bootstrap: &str,
    item: &str,
    field: &str,
) -> Result<Option<IssuedAcquisition>> {
    if !exact_name(consumer)
        || !exact_name(item)
        || !exact_name(field)
        || bootstrap.is_empty()
    {
        return Ok(None);
    }
    let vault = Vault::open(vault_path())?;
    if !tokens::token_allows_acquisition(&vault, consumer, bootstrap, item, field)? {
        return Ok(None);
    }
    validate_target(&vault, item, field)?;

    let path = state_path();
    let _lock = acquire_lock(&path)?;
    let mut state = load_state(&path)?;
    let now = now_epoch()?;
    purge_expired(&mut state, now)?;
    let expires_at = now.checked_add(ttl_seconds()?).context("acquisition expiry overflow")?;
    let token = crypto::random_token()?;
    let hash = crypto::sha256_hex(&token)?;
    let tokens = state
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .context("acquisition tokens section")?;
    if tokens.contains_key(&hash) {
        bail!("acquisition token collision");
    }
    tokens.insert(hash, json!({
        "consumer": consumer,
        "item": item,
        "field": field,
        "expires_at": expires_at,
    }));
    save_state(&path, &state)?;
    Ok(Some(IssuedAcquisition { token, expires_at }))
}

pub fn consume(
    consumer: &str,
    presented: &str,
    item: &str,
    field: &str,
) -> Result<Option<Value>> {
    if !exact_name(consumer) || !exact_name(item) || !exact_name(field) || presented.is_empty() {
        return Ok(None);
    }
    let hash = crypto::sha256_hex(presented)?;
    let path = state_path();
    let _lock = acquire_lock(&path)?;
    let mut state = load_state(&path)?;
    let now = now_epoch()?;
    let record = state
        .get("tokens")
        .and_then(Value::as_object)
        .and_then(|tokens| tokens.get(&hash))
        .cloned();
    let Some(record) = record else {
        return Ok(None);
    };
    let expired = match record.get("expires_at").and_then(Value::as_u64) {
        Some(expiry) => expiry <= now,
        None => true,
    };
    if expired {
        state
            .get_mut("tokens")
            .and_then(Value::as_object_mut)
            .context("acquisition tokens section")?
            .remove(&hash);
        save_state(&path, &state)?;
        return Ok(None);
    }
    let bound = record.get("consumer").and_then(Value::as_str) == Some(consumer)
        && record.get("item").and_then(Value::as_str) == Some(item)
        && record.get("field").and_then(Value::as_str) == Some(field);
    if !bound {
        return Ok(None);
    }

    let vault = Vault::open(vault_path())?;
    let value = vault
        .get_item(item)?
        .as_object()
        .and_then(|object| object.get(field))
        .cloned()
        .context("acquisition field no longer exists on item")?;
    state
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .context("acquisition tokens section")?
        .remove(&hash);
    save_state(&path, &state)?;
    Ok(Some(value))
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "acquisition-request" => {
            let consumer = positionals.first().context(
                "usage: acquisition-request <consumer> <item> <field> --token BOOTSTRAP",
            )?;
            let item = positionals.get("1".parse::<usize>()?).context(
                "usage: acquisition-request <consumer> <item> <field> --token BOOTSTRAP",
            )?;
            let field = positionals.get("2".parse::<usize>()?).context(
                "usage: acquisition-request <consumer> <item> <field> --token BOOTSTRAP",
            )?;
            let bootstrap = flags.get("token").context("--token required")?;
            let Some(issued) = issue(consumer, bootstrap, item, field)? else {
                return Ok(Some(json!({"ok": false, "error": "unauthorized"})));
            };
            crate::runtime::audit::append(
                "acquisition-issued",
                &json!({"consumer": consumer, "item": item, "field": field, "expires_at": issued.expires_at}),
            )?;
            Ok(Some(json!({
                "ok": true,
                "consumer": consumer,
                "item": item,
                "field": field,
                "expires_at": issued.expires_at,
                "token": issued.token,
            })))
        }
        "acquisition-read" => {
            let consumer = positionals.first().context(
                "usage: acquisition-read <consumer> <item> <field> --token ACQUISITION",
            )?;
            let item = positionals.get("1".parse::<usize>()?).context(
                "usage: acquisition-read <consumer> <item> <field> --token ACQUISITION",
            )?;
            let field = positionals.get("2".parse::<usize>()?).context(
                "usage: acquisition-read <consumer> <item> <field> --token ACQUISITION",
            )?;
            let presented = flags.get("token").context("--token required")?;
            let Some(value) = consume(consumer, presented, item, field)? else {
                return Ok(Some(json!({"ok": false, "error": "unauthorized"})));
            };
            crate::runtime::audit::append(
                "acquisition-consumed",
                &json!({"consumer": consumer, "item": item, "field": field}),
            )?;
            Ok(Some(json!({"ok": true, "consumer": consumer, "item": item, "field": field, "value": value})))
        }
        _ => Ok(None),
    }
}
