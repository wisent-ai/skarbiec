use aes::Aes128;
use anyhow::{bail, Context, Result};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use pbkdf2::pbkdf2_hmac;
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use sha1::Sha1;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::{Zeroize, Zeroizing};

use super::items;
use super::vault::Vault;

type ChromeDecryptor = cbc::Decryptor<Aes128>;

const CHROME_PREFIX: &[u8] = b"v10";
const CHROME_SALT: &[u8] = b"saltysalt";
const CHROME_IV: [u8; 16] = [b' '; 16];
const CHROME_PBKDF2_ITERATIONS: u32 = 1003;
const CHROME_KEY_BYTES: usize = 16;

struct LocalCard {
    profile: String,
    guid: String,
    holder_name: String,
    expiry_month: i64,
    expiry_year: i64,
    number: Zeroizing<String>,
}

struct PreparedCard {
    profile: String,
    holder_name: String,
    expiry_month: i64,
    expiry_year: i64,
    number: Zeroizing<String>,
    cvc: Zeroizing<String>,
    last4: String,
}

struct MaskedCard {
    profile: String,
    holder_name: String,
    expiry_month: i64,
    expiry_year: i64,
    network: String,
    last4: String,
}

pub fn default_chrome_root() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not configured")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("Google")
        .join("Chrome"))
}

fn selected_profiles(root: &Path, requested: Option<&str>) -> Result<Vec<String>> {
    let local_state_path = root.join("Local State");
    let local_state: Value =
        serde_json::from_slice(&std::fs::read(&local_state_path).with_context(|| {
            format!(
                "read Chrome profile registry at {}",
                local_state_path.display()
            )
        })?)
        .context("parse Chrome profile registry")?;
    let known = local_state
        .get("profile")
        .and_then(|value| value.get("info_cache"))
        .and_then(Value::as_object)
        .context("Chrome profile registry has no profile info cache")?;

    let mut profiles: Vec<String> = if let Some(csv) = requested {
        let values: Vec<String> = csv
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect();
        if values.is_empty() {
            bail!("--profiles must name at least one Chrome profile directory");
        }
        for value in &values {
            if value.contains('/') || value.contains('\\') || value == "." || value == ".." {
                bail!("invalid Chrome profile directory");
            }
            if !known.contains_key(value) {
                bail!("unknown Chrome profile directory: {value}");
            }
        }
        values
    } else {
        known.keys().cloned().collect()
    };
    profiles.sort();
    profiles.dedup();
    Ok(profiles)
}

fn open_web_data(root: &Path, profile: &str) -> Result<Option<Connection>> {
    let path = root.join(profile).join("Web Data");
    if !path.is_file() {
        return Ok(None);
    }
    let uri = format!("file:{}?immutable=1", path.display());
    Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map(Some)
    .with_context(|| format!("open Chrome payment store for profile {profile}"))
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )
        .context("inspect Chrome payment schema")
}

fn chrome_key() -> Result<Zeroizing<[u8; CHROME_KEY_BYTES]>> {
    let output = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-w", "-s", "Chrome Safe Storage"])
        .output()
        .context("read Chrome Safe Storage key from macOS Keychain")?;
    if !output.status.success() {
        bail!("macOS Keychain did not release the Chrome Safe Storage key");
    }
    let mut password = Zeroizing::new(output.stdout);
    while matches!(password.last(), Some(b'\n' | b'\r')) {
        password.pop();
    }
    if password.is_empty() {
        bail!("Chrome Safe Storage key is empty");
    }
    let mut key = Zeroizing::new([0_u8; CHROME_KEY_BYTES]);
    pbkdf2_hmac::<Sha1>(
        password.as_slice(),
        CHROME_SALT,
        CHROME_PBKDF2_ITERATIONS,
        key.as_mut(),
    );
    Ok(key)
}

fn decrypt_chrome(
    mut encrypted: Vec<u8>,
    key: &[u8; CHROME_KEY_BYTES],
) -> Result<Zeroizing<String>> {
    if !encrypted.starts_with(CHROME_PREFIX) || encrypted.len() <= CHROME_PREFIX.len() {
        encrypted.zeroize();
        bail!("unsupported Chrome card encryption format");
    }
    encrypted.copy_within(CHROME_PREFIX.len().., 0);
    encrypted.truncate(encrypted.len() - CHROME_PREFIX.len());
    let mut plaintext = Zeroizing::new(encrypted);
    let length = ChromeDecryptor::new(key.into(), (&CHROME_IV).into())
        .decrypt_padded_mut::<Pkcs7>(&mut plaintext)
        .map_err(|_| anyhow::anyhow!("Chrome card decryption failed"))?
        .len();
    plaintext.truncate(length);
    let bytes = std::mem::take(plaintext.as_mut());
    match String::from_utf8(bytes) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(error) => {
            let mut invalid = error.into_bytes();
            invalid.zeroize();
            bail!("Chrome card plaintext is not UTF-8");
        }
    }
}

fn local_cvc(
    connection: &Connection,
    key: &[u8; CHROME_KEY_BYTES],
) -> Result<HashMap<String, Zeroizing<String>>> {
    if !table_exists(connection, "local_stored_cvc")? {
        return Ok(HashMap::new());
    }
    let mut statement = connection
        .prepare("SELECT guid,value_encrypted FROM local_stored_cvc")
        .context("prepare Chrome local CVC query")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .context("query Chrome local CVC values")?;
    let mut values = HashMap::new();
    for row in rows {
        let (guid, encrypted) = row.context("read Chrome local CVC value")?;
        values.insert(guid, decrypt_chrome(encrypted, key)?);
    }
    Ok(values)
}

fn read_local_cards(
    connection: &Connection,
    profile: &str,
    key: &[u8; CHROME_KEY_BYTES],
) -> Result<Vec<LocalCard>> {
    if !table_exists(connection, "credit_cards")? {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT guid,name_on_card,expiration_month,expiration_year,card_number_encrypted \
             FROM credit_cards ORDER BY guid",
        )
        .context("prepare Chrome local card query")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .context("query Chrome local cards")?;
    let mut cards = Vec::new();
    for row in rows {
        let (guid, holder_name, expiry_month, expiry_year, encrypted) =
            row.context("read Chrome local card")?;
        cards.push(LocalCard {
            profile: profile.to_string(),
            guid,
            holder_name,
            expiry_month,
            expiry_year,
            number: decrypt_chrome(encrypted, key)?,
        });
    }
    Ok(cards)
}

fn read_masked_cards(connection: &Connection, profile: &str) -> Result<Vec<MaskedCard>> {
    if !table_exists(connection, "masked_credit_cards")? {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT name_on_card,exp_month,exp_year,network,last_four \
             FROM masked_credit_cards ORDER BY instrument_id",
        )
        .context("prepare Chrome cloud card query")?;
    let rows = statement
        .query_map([], |row| {
            Ok(MaskedCard {
                profile: profile.to_string(),
                holder_name: row.get(0)?,
                expiry_month: row.get(1)?,
                expiry_year: row.get(2)?,
                network: row.get(3)?,
                last4: row.get(4)?,
            })
        })
        .context("query Chrome cloud cards")?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("read Chrome cloud cards")
}

fn read_server_cvc(
    connection: &Connection,
    key: &[u8; CHROME_KEY_BYTES],
) -> Result<Vec<(String, Zeroizing<String>)>> {
    if !table_exists(connection, "masked_credit_cards")?
        || !table_exists(connection, "server_stored_cvc")?
    {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT m.last_four,c.value_encrypted FROM masked_credit_cards m \
             JOIN server_stored_cvc c ON c.instrument_id=m.instrument_id",
        )
        .context("prepare Chrome cloud CVC query")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .context("query Chrome cloud CVC values")?;
    let mut values = Vec::new();
    for row in rows {
        let (last4, encrypted) = row.context("read Chrome cloud CVC value")?;
        values.push((last4, decrypt_chrome(encrypted, key)?));
    }
    Ok(values)
}

fn safe_profile_tag(profile: &str) -> String {
    profile
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn card_id(last4: &str, occurrence: usize) -> String {
    if occurrence == 1 {
        format!("payment-card-{last4}")
    } else {
        format!("payment-card-{last4}-{occurrence}")
    }
}

pub fn import_into_vault(
    vault: &mut Vault,
    chrome_root: &Path,
    requested_profiles: Option<&str>,
    replace: bool,
) -> Result<Value> {
    let profiles = selected_profiles(chrome_root, requested_profiles)?;
    let key = chrome_key()?;
    let mut masked = Vec::new();
    let mut server_cvc: HashMap<String, Zeroizing<String>> = HashMap::new();
    let mut ambiguous_cvc = HashSet::new();

    for profile in &profiles {
        let Some(connection) = open_web_data(chrome_root, profile)? else {
            continue;
        };
        masked.extend(read_masked_cards(&connection, profile)?);
        for (last4, cvc) in read_server_cvc(&connection, &key)? {
            if ambiguous_cvc.contains(&last4) {
                continue;
            }
            match server_cvc.get(&last4) {
                Some(existing) if existing.as_str() != cvc.as_str() => {
                    server_cvc.remove(&last4);
                    ambiguous_cvc.insert(last4);
                }
                Some(_) => {}
                None => {
                    server_cvc.insert(last4, cvc);
                }
            }
        }
    }

    let mut prepared: Vec<PreparedCard> = Vec::new();
    let mut skipped = Vec::new();
    for profile in &profiles {
        let Some(connection) = open_web_data(chrome_root, profile)? else {
            continue;
        };
        let mut cvc_by_guid = local_cvc(&connection, &key)?;
        for local in read_local_cards(&connection, profile, &key)? {
            let last4 = local
                .number
                .get(local.number.len().saturating_sub(4)..)
                .unwrap_or("")
                .to_string();
            if prepared
                .iter()
                .any(|existing| existing.number.as_str() == local.number.as_str())
            {
                skipped.push(json!({
                    "profile": local.profile,
                    "last4": last4,
                    "reason": "duplicate_local_card"
                }));
                continue;
            }
            if local.holder_name.trim().is_empty() {
                skipped.push(json!({
                    "profile": local.profile,
                    "last4": last4,
                    "reason": "missing_holder_name"
                }));
                continue;
            }
            let cvc = cvc_by_guid.remove(&local.guid).or_else(|| {
                server_cvc
                    .get(&last4)
                    .map(|value| Zeroizing::new(value.to_string()))
            });
            let Some(cvc) = cvc else {
                skipped.push(json!({
                    "profile": local.profile,
                    "last4": last4,
                    "reason": "missing_cvc"
                }));
                continue;
            };
            prepared.push(PreparedCard {
                profile: local.profile,
                holder_name: local.holder_name,
                expiry_month: local.expiry_month,
                expiry_year: local.expiry_year,
                number: local.number,
                cvc,
                last4,
            });
        }
    }

    for card in masked {
        skipped.push(json!({
            "profile": card.profile,
            "last4": card.last4,
            "holder_name": card.holder_name,
            "expiry_month": card.expiry_month,
            "expiry_year": card.expiry_year,
            "network": card.network,
            "reason": "cloud_card_requires_interactive_unmask"
        }));
    }

    prepared.sort_by(|left, right| {
        left.last4
            .cmp(&right.last4)
            .then_with(|| left.profile.cmp(&right.profile))
    });
    let mut occurrences: HashMap<String, usize> = HashMap::new();
    let mut imported = Vec::new();
    for card in prepared {
        let occurrence = occurrences.entry(card.last4.clone()).or_default();
        *occurrence += 1;
        let id = card_id(&card.last4, *occurrence);
        if vault.contains_item(&id) && !replace {
            skipped.push(json!({
                "profile": card.profile,
                "last4": card.last4,
                "id": id,
                "reason": "already_exists"
            }));
            continue;
        }
        let value = json!({
            "holder_name": card.holder_name,
            "number": card.number.as_str(),
            "expiry_month": card.expiry_month.to_string(),
            "expiry_year": card.expiry_year.to_string(),
            "cvc": card.cvc.as_str(),
            "label": format!("Chrome {}", card.profile)
        });
        let (secret, last4) = match items::payment_card_from_value(value) {
            Ok(value) => value,
            Err(error) => {
                skipped.push(json!({
                    "profile": card.profile,
                    "last4": card.last4,
                    "reason": "validation_failed",
                    "detail": error.to_string()
                }));
                continue;
            }
        };
        let tags = vec![
            "payment-card".to_string(),
            "chrome-import".to_string(),
            format!("chrome-profile:{}", safe_profile_tag(&card.profile)),
        ];
        vault.set_item(&id, items::PAYMENT_CARD_TYPE, secret.as_value(), &[], &tags)?;
        imported.push(json!({
            "id": id,
            "last4": last4,
            "profile": card.profile
        }));
    }

    Ok(json!({
        "ok": true,
        "imported": imported,
        "skipped": skipped
    }))
}
