// Request-only bootstrap grants exchange for short-lived, field-bound,
// single-use bearers. SQLite IMMEDIATE transactions make the consume decision
// atomic across concurrent CLI and HTTP processes.

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::access::tokens;
use crate::core::{crypto, vault::Vault, vault_path};

fn private_mode() -> Result<u32> {
    u32::from_str_radix("600", "8".parse()?).context("private acquisition state mode")
}

fn unsafe_mode_bits() -> Result<u32> {
    u32::from_str_radix("077", "8".parse()?).context("unsafe acquisition state mode bits")
}

fn state_path() -> PathBuf {
    if let Ok(path) = std::env::var("SKARBIEC_ACQUISITION_FILE") {
        return PathBuf::from(path);
    }
    let vault = vault_path();
    let name = vault
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.acquisitions.sqlite"))
        .unwrap_or_else(|| "skarbiec.vault.acquisitions.sqlite".to_string());
    vault.with_file_name(name)
}

fn validate_owned_regular(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!("acquisition state must be an owner-controlled regular file");
    }
    if metadata.mode() & unsafe_mode_bits()? != u32::MIN {
        bail!("acquisition state permissions must not grant group or other access");
    }
    Ok(())
}

fn open_state() -> Result<Connection> {
    let path = state_path();
    let parent = path.parent().context("acquisition state has no parent")?;
    fs::create_dir_all(parent)?;
    if path.exists() {
        validate_owned_regular(&path)?;
    } else {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(private_mode()?)
            .open(&path)
            .context("create acquisition state")?;
        file.sync_all()?;
        fs::set_permissions(&path, fs::Permissions::from_mode(private_mode()?))?;
        validate_owned_regular(&path)?;
    }
    let connection = Connection::open(&path).context("open acquisition state")?;
    connection.busy_timeout(Duration::from_secs("5".parse()?))?;
    connection.execute_batch(
        "PRAGMA journal_mode=DELETE;
         PRAGMA synchronous=FULL;
         CREATE TABLE IF NOT EXISTS acquisitions(
           token_hash TEXT PRIMARY KEY,
           consumer TEXT NOT NULL,
           item TEXT NOT NULL,
           field TEXT NOT NULL,
           expires_at INTEGER NOT NULL
         );",
    )?;
    validate_owned_regular(&path)?;
    Ok(connection)
}

fn now_epoch() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock before epoch")?
        .as_secs())
}

fn ttl_seconds() -> Result<u64> {
    let ttl: u64 = std::env::var("SKARBIEC_ACQUISITION_TTL_SECONDS")
        .unwrap_or_else(|_| "30".to_string())
        .parse()
        .context("SKARBIEC_ACQUISITION_TTL_SECONDS must be an integer")?;
    let maximum: u64 = "300".parse()?;
    if ttl == u64::MIN || ttl > maximum {
        bail!("SKARBIEC_ACQUISITION_TTL_SECONDS must be between one and 300");
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
    if !value
        .as_object()
        .is_some_and(|object| object.contains_key(field))
    {
        bail!("acquisition scope names a missing item field");
    }
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

    let now = now_epoch()?;
    let expires_at = now
        .checked_add(ttl_seconds()?)
        .context("acquisition expiry overflow")?;
    let token = crypto::random_token()?;
    let hash = crypto::sha256_hex(&token)?;
    let mut connection = open_state()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute("DELETE FROM acquisitions WHERE expires_at<=?1", [now])?;
    transaction.execute(
        "INSERT INTO acquisitions(token_hash,consumer,item,field,expires_at) VALUES(?1,?2,?3,?4,?5)",
        params![hash, consumer, item, field, expires_at],
    )?;
    transaction.commit()?;
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
    let vault = Vault::open(vault_path())?;
    let mut connection = open_state()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let record: Option<(String, String, String, u64)> = transaction
        .query_row(
            "SELECT consumer,item,field,expires_at FROM acquisitions WHERE token_hash=?1",
            [&hash],
            |row| {
                Ok((
                    row.get("consumer")?,
                    row.get("item")?,
                    row.get("field")?,
                    row.get("expires_at")?,
                ))
            },
        )
        .optional()?;
    let Some((bound_consumer, bound_item, bound_field, expires_at)) = record else {
        return Ok(None);
    };
    let now = now_epoch()?;
    if expires_at <= now {
        transaction.execute("DELETE FROM acquisitions WHERE token_hash=?1", [&hash])?;
        transaction.commit()?;
        return Ok(None);
    }
    if bound_consumer != consumer || bound_item != item || bound_field != field {
        return Ok(None);
    }
    let value = vault
        .get_item(item)?
        .as_object()
        .and_then(|object| object.get(field))
        .cloned()
        .context("acquisition field no longer exists on item")?;
    let removed = transaction.execute("DELETE FROM acquisitions WHERE token_hash=?1", [&hash])?;
    if removed != std::iter::once(()).count() {
        bail!("acquisition bearer was not consumed exactly once");
    }
    transaction.commit()?;
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
