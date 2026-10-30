//! `skarbiec keys import [--gnupg-home DIR] [--keys FPR[,FPR...]]`: bring the
//! keys a vault names out of a GnuPG home into the vault's key file, once,
//! by reading GnuPG's own files. Nothing is run: the public keys come from
//! keyboxd's `public-keys.d/pubring.db` (or the older `pubring.kbx`), the
//! secret halves from gpg-agent's `private-keys-v1.d/<keygrip>.key`. A
//! protected secret key is opened with the unlock phrase Skarbiec is
//! configured with (`SKARBIEC_UNLOCK_FILE`, `SKARBIEC_UNLOCK`).

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use skarbiec_crypto::openpgp::agent::{is_protected, key_file_public, read_key_file};
use skarbiec_crypto::openpgp::keyboxd::{read_keybox, read_pubring_db};
use skarbiec_crypto::openpgp::keys::{fingerprint, parse_public_keys};
use skarbiec_crypto::openpgp::{hex_upper, packets, write_packet};
use skarbiec_crypto::wipe::Secret;

use super::keyring::{self, NewKey, SecretHalf};

/// The OpenPGP packets a public key is carried in: the primary key, user
/// ids, user attributes, subkeys and signatures. Trust and ring packets a
/// keyring adds are its own bookkeeping and are left behind.
const KEY_PACKETS: [u8; 5] = [6, 13, 17, 14, 2];

/// The GnuPG home to read: `--gnupg-home`, else `GNUPGHOME`, else `~/.gnupg`,
/// as gpg itself chooses.
fn gnupg_home(flags: &HashMap<String, String>) -> PathBuf {
    if let Some(named) = flags.get("gnupg-home") {
        return PathBuf::from(named);
    }
    if let Some(configured) = crate::core::env::path("GNUPGHOME") {
        return configured;
    }
    crate::core::home_dir().join(".gnupg")
}

/// Every keyblock the GnuPG home's public keyring holds.
fn keyblocks(home: &Path) -> Result<Vec<Vec<u8>>> {
    let database = home.join("public-keys.d").join("pubring.db");
    let keybox = home.join("pubring.kbx");
    let stored = if let Some(bytes) = read_bytes(&database)? {
        read_pubring_db(&bytes).map_err(|error| {
            anyhow::anyhow!(
                "read keyboxd's key database {}: {error}; if gpg is writing it now, run the import again",
                database.display()
            )
        })?
    } else if let Some(bytes) = read_bytes(&keybox)? {
        read_keybox(&bytes)
            .map_err(|error| anyhow::anyhow!("read the keybox {}: {error}", keybox.display()))?
    } else {
        bail!(
            "{} holds no public keyring (neither {} nor {}); name the GnuPG home that holds the \
             vault's keys with --gnupg-home <dir>",
            home.display(),
            database.display(),
            keybox.display()
        );
    };
    Ok(stored.into_iter().map(|key| key.keyblock).collect())
}

fn read_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// The fingerprint a keyblock's primary key has, and the keyblock reduced
/// to the packets a public key is carried in.
fn primary(keyblock: &[u8]) -> Result<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut first = None;
    for packet in packets(keyblock).map_err(|error| anyhow::anyhow!("{error}"))? {
        if packet.tag == 6 && first.is_none() {
            first = Some(hex_upper(&fingerprint(&packet.body)));
        }
        if KEY_PACKETS.contains(&packet.tag) {
            out.extend(write_packet(packet.tag, &packet.body));
        }
    }
    let first = first.context("a keyblock holds no primary key")?;
    Ok((first, out))
}

/// gpg-agent's key files, by the public point each holds (`0x40 || key`).
fn agent_files(home: &Path) -> Result<HashMap<Vec<u8>, (PathBuf, String)>> {
    let directory = home.join("private-keys-v1.d");
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error).with_context(|| format!("list {}", directory.display())),
    };
    let mut files = HashMap::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("list {}", directory.display()))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("key") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read gpg-agent key file {}", path.display()))?;
        // A file of a kind this reads nothing from (an RSA key, a card stub)
        // names no Curve25519 point and cannot be a vault key's.
        if let Ok((_curve, q)) = key_file_public(&text) {
            files.insert(q, (path, text));
        }
    }
    Ok(files)
}

fn point(key: &[u8; 32]) -> Vec<u8> {
    let mut q = vec![0x40];
    q.extend_from_slice(key);
    q
}

/// The secret half of a key from its two agent files, or why it is not here.
fn secret_half(
    files: &HashMap<Vec<u8>, (PathBuf, String)>,
    ed25519: &[u8; 32],
    x25519: &[u8; 32],
    phrase: Option<&Secret>,
) -> std::result::Result<Option<SecretHalf>, String> {
    let (Some((signing_path, signing)), Some((sealing_path, sealing))) =
        (files.get(&point(ed25519)), files.get(&point(x25519)))
    else {
        return Ok(None);
    };
    let open = |path: &Path, text: &str| {
        let passphrase = if is_protected(text) {
            match phrase {
                Some(phrase) => Some(phrase.expose()),
                None => {
                    return Err(format!(
                        "{} is protected by a passphrase and no unlock phrase is configured: write \
                         the passphrase to the owner-only file SKARBIEC_UNLOCK_FILE names (default \
                         ~/.stado/skarbiec-unlock) and import again",
                        path.display()
                    ))
                }
            }
        } else {
            None
        };
        read_key_file(text, passphrase).map_err(|error| {
            format!(
                "{} does not open: {error}; if it is protected, the configured unlock phrase \
                 is not its passphrase",
                path.display()
            )
        })
    };
    let signing = open(signing_path, signing)?;
    let sealing = open(sealing_path, sealing)?;
    let seed = signing
        .ed25519_seed()
        .map_err(|error| format!("{}: {error}", signing_path.display()))?;
    let scalar = sealing
        .x25519_secret()
        .map_err(|error| format!("{}: {error}", sealing_path.display()))?;
    Ok(Some(SecretHalf {
        seed: Secret::new(seed.to_vec()),
        scalar: Secret::new(scalar.to_vec()),
    }))
}

/// The fingerprints to import: `--keys`, else every key the vault names.
fn wanted(flags: &HashMap<String, String>) -> Result<Vec<String>> {
    if let Some(listed) = flags.get("keys") {
        let keys: Vec<String> = listed
            .split(',')
            .map(|fpr| fpr.trim().to_ascii_uppercase())
            .filter(|fpr| !fpr.is_empty())
            .collect();
        if let Some(bad) = keys
            .iter()
            .find(|fpr| fpr.len() != 40 || !fpr.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(crate::cli::args::Usage(format!(
                "--keys {bad}: name each key by its 40-digit fingerprint"
            ))
            .into());
        }
        return Ok(keys);
    }
    let vault = crate::core::vault::Vault::open(crate::core::vault_path()).context(
        "keys import reads which keys to bring from the vault; with no vault here, name them with --keys <fingerprint,...>",
    )?;
    let mut keys: Vec<String> = vault
        .section("recipients", "uid -> recipient")?
        .values()
        .filter_map(|entry| entry.get("fingerprint").and_then(Value::as_str))
        .filter(|fpr| !fpr.is_empty())
        .map(str::to_ascii_uppercase)
        .collect();
    let recovery = vault.recovery_fpr().to_ascii_uppercase();
    if !recovery.is_empty() {
        keys.push(recovery);
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

pub fn run(flags: &HashMap<String, String>) -> Result<Value> {
    if let Some(flag) = flags
        .keys()
        .find(|flag| !matches!(flag.as_str(), "gnupg-home" | "keys"))
    {
        return Err(crate::cli::args::Usage(format!(
            "keys import takes --gnupg-home <dir> and --keys <fingerprint,...>; it was given --{flag}"
        ))
        .into());
    }
    let home = gnupg_home(flags);
    let wanted = wanted(flags)?;
    let blocks = keyblocks(&home)?;
    let files = agent_files(&home)?;
    let phrase = keyring::unlock_phrase()?;
    let mut found: HashMap<String, Vec<u8>> = HashMap::new();
    for block in &blocks {
        // A keyblock this cannot read (another algorithm, damage) is no
        // vault key's; a vault key's own block is reported below if missing.
        if let Ok((fpr, packets)) = primary(block) {
            if wanted.contains(&fpr) {
                found.insert(fpr, packets);
            }
        }
    }
    let target = keyring::path();
    let mut rows = Vec::new();
    let mut missing = Vec::new();
    let mut to_add = Vec::new();
    for fpr in &wanted {
        let Some(packets) = found.remove(fpr) else {
            missing.push(fpr.clone());
            continue;
        };
        let public = parse_public_keys(&packets)
            .map_err(|error| anyhow::anyhow!("key {fpr} in {}: {error}", home.display()))?
            .into_iter()
            .next()
            .with_context(|| format!("key {fpr} in {} holds no key", home.display()))?;
        let Some(subkey) = public.subkeys.first() else {
            bail!(
                "key {fpr} in {} has no Curve25519 encryption subkey, so no item can be sealed \
                 to it; give its holder a new key (`skarbiec recipient rekey`)",
                home.display()
            );
        };
        let (secret, state) =
            match secret_half(&files, &public.ed25519, &subkey.x25519, phrase.as_ref()) {
                Ok(Some(half)) => (Some(half), "imported".to_string()),
                Ok(None) => (None, "not on this host".to_string()),
                Err(why) => bail!("the secret half of {fpr}: {why}"),
            };
        rows.push(json!({
            "fingerprint": fpr,
            "user_ids": public.user_ids,
            "secret_half": state,
        }));
        to_add.push(NewKey { packets, secret });
    }
    let added = keyring::add(&target, to_add)?;
    for (row, (_, changed)) in rows.iter_mut().zip(&added) {
        row["changed"] = json!(changed);
    }
    if !missing.is_empty() {
        bail!(
            "{} holds no public key {}, which the vault names; the {} other key(s) were written \
             to {}. Import those keys' public halves into that GnuPG home (or name the home that \
             holds them with --gnupg-home), then run keys import again",
            home.display(),
            missing.join(", "),
            rows.len(),
            target.display()
        );
    }
    crate::runtime::audit::append(
        "keys-import",
        &json!({"from": home.display().to_string(), "keys": rows}),
    )?;
    Ok(json!({
        "ok": true,
        "from": home.display().to_string(),
        "key_file": target.display().to_string(),
        "keys": rows,
    }))
}
