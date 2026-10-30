// The keys a vault names, in the key file beside it: making one, finding one
// by user id, importing and exporting public halves, and telling whether the
// secret half of one is on this host.

use anyhow::{bail, Context, Result};

use skarbiec_crypto::openpgp::armor::armor;
use skarbiec_crypto::openpgp::keys::{parse_public_keys, transferable_public_key, PublicKey};
use skarbiec_crypto::openpgp::{packets, write_packet};
use skarbiec_crypto::wipe::Secret;

use super::keyring::{self, NewKey, SecretHalf};

/// Make a new key pair for a user id in this vault's key file, returning
/// its fingerprint: an Ed25519 primary key that signs and a Curve25519
/// subkey items are sealed to, both from the operating system's random source.
pub fn generate_key(uid: &str) -> Result<String> {
    let seed = Secret::new(
        skarbiec_crypto::random::key()
            .context("draw the Ed25519 seed of a new key")?
            .to_vec(),
    );
    let scalar = Secret::new(
        skarbiec_crypto::random::key()
            .context("draw the X25519 scalar of a new key")?
            .to_vec(),
    );
    let seed_bytes: [u8; 32] = seed.expose().try_into().context("a 32-byte seed")?;
    let scalar_bytes: [u8; 32] = scalar.expose().try_into().context("a 32-byte scalar")?;
    let created = u32::try_from(crate::core::clock::epoch_seconds()?)
        .context("the clock is past what an OpenPGP key can state (2106)")?;
    let packets = transferable_public_key(
        &seed_bytes,
        &skarbiec_crypto::x25519::public_key(&scalar_bytes),
        uid,
        created,
    );
    let path = keyring::path();
    let added = keyring::add(
        &path,
        vec![NewKey {
            packets,
            secret: Some(SecretHalf {
                seed: Some(seed),
                scalar,
            }),
        }],
    )?;
    let (fingerprint, _) = added
        .into_iter()
        .next()
        .context("the key file answered no key for the one added")?;
    Ok(fingerprint)
}

/// The fingerprint of the key whose user id is exactly `uid` in this vault's
/// key file.
pub fn fingerprint_for(uid: &str) -> Result<Option<String>> {
    Ok(keyring::load()?.find(uid).map(|key| key.fingerprint()))
}

/// Every key an armored public key block holds, one packet run per key.
fn split_keys(armored: &str) -> Result<Vec<(Vec<u8>, PublicKey)>> {
    if armored.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
        bail!(
            "this is a secret key block; Skarbiec takes only public keys here: export the public \
             half (`gpg --armor --export <uid>`), or bring a secret key gpg kept with `skarbiec keys import`"
        );
    }
    let data = keyring::public_packets(armored)
        .context("read the public key block (it must be an armored OpenPGP public key)")?;
    let mut runs: Vec<Vec<u8>> = Vec::new();
    for packet in packets(&data).map_err(|error| anyhow::anyhow!("{error}"))? {
        if packet.tag == 6 || runs.is_empty() {
            runs.push(Vec::new());
        }
        if let Some(run) = runs.last_mut() {
            run.extend(write_packet(packet.tag, &packet.body));
        }
    }
    let mut keys = Vec::new();
    for run in runs {
        let public = parse_public_keys(&run)
            .map_err(|error| anyhow::anyhow!("the public key block: {error}"))?
            .into_iter()
            .next()
            .context("the public key block holds no key")?;
        keys.push((run, public));
    }
    if keys.is_empty() {
        bail!("the public key block holds no key");
    }
    Ok(keys)
}

/// The fingerprint of the primary key an armored key holds, read without
/// importing it, so a key replacing another under the same user id is named
/// exactly rather than found by that user id.
pub fn fingerprint_of_armored(armored: &str) -> Result<String> {
    let keys = split_keys(armored)?;
    match keys.as_slice() {
        [(_, key)] => Ok(key.fingerprint_hex()),
        more => bail!(
            "the key file holds {} keys ({}); give it one key",
            more.len(),
            more.iter()
                .map(|(_, key)| key.fingerprint_hex())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// What the key file says about one public key's life: the moment it expires
/// (none when it never does) and its validity letter, `e` expired and `r`
/// revoked, empty otherwise. A key either way still opens what was sealed to
/// it; new writes to it are the holder's to stop.
pub struct KeyValidity {
    pub expires_epoch: Option<i64>,
    pub validity: String,
}

/// The validity of the key `fingerprint` names, or none when the key file
/// does not hold it.
pub fn key_validity(fingerprint: &str) -> Result<Option<KeyValidity>> {
    let keyring = keyring::load()?;
    let Some(key) = keyring.find(fingerprint) else {
        return Ok(None);
    };
    let expires_epoch = key
        .public
        .expires_after
        .filter(|after| *after != 0)
        .map(|after| i64::from(key.public.created) + i64::from(after));
    let now = i64::try_from(crate::core::clock::epoch_seconds()?)
        .context("the clock does not fit a signed number of seconds")?;
    let validity = if key.public.revoked {
        "r"
    } else if expires_epoch.is_some_and(|at| at <= now) {
        "e"
    } else {
        ""
    };
    Ok(Some(KeyValidity {
        expires_epoch,
        validity: validity.to_string(),
    }))
}

/// Whether the secret half of this key (fingerprint or key id) is in this
/// vault's key file. The public half proves nothing: stored ciphertext opens
/// only for whoever holds a secret key.
pub fn secret_key_present(fingerprint: &str) -> Result<bool> {
    let keyring = keyring::load()?;
    Ok(keyring
        .find(fingerprint)
        .is_some_and(|key| key.holds_secret()))
}

/// Whether this host can sign as the key `fingerprint` names (an audit epoch
/// checkpoint signs as the vault owner): `Err` says why not — no secret half,
/// one that will not unlock, or one imported for decryption only.
pub fn can_sign_as(fingerprint: &str) -> Result<std::result::Result<(), String>> {
    let keyring = keyring::load()?;
    let file = keyring::path();
    let Some(key) = keyring.find(fingerprint) else {
        return Ok(Err(format!(
            "{} holds no key {fingerprint}",
            file.display()
        )));
    };
    Ok(key
        .secret(&file)
        .and_then(|secret| secret.signing_seed(fingerprint).map(drop))
        .map_err(|why| format!("{why:#}")))
}

/// The key file a restore from backup has to bring back for this vault.
pub fn key_file() -> std::path::PathBuf {
    keyring::path()
}

/// Add every public key an armored key block holds to this vault's key file;
/// answers each key's fingerprint and whether the file changed for it.
pub fn import_key(armored: &str) -> Result<Vec<(String, bool)>> {
    let keys = split_keys(armored)?
        .into_iter()
        .map(|(packets, _)| NewKey {
            packets,
            secret: None,
        })
        .collect();
    keyring::add(&keyring::path(), keys)
}

/// A recipient's armored public key, for sharing the vault.
pub fn export_public_key(fingerprint: &str) -> Result<String> {
    let keyring = keyring::load()?;
    let key = keyring.require(fingerprint)?;
    Ok(armor(&key.packets, "PGP PUBLIC KEY BLOCK"))
}

/// The public keys `fingerprints` name, in one armored block; refused
/// naming the first the key file lacks.
pub fn export_public_keys(fingerprints: &[String]) -> Result<String> {
    let keyring = keyring::load()?;
    let mut packets = Vec::new();
    for fingerprint in fingerprints {
        packets.extend_from_slice(&keyring.require(fingerprint)?.packets);
    }
    Ok(armor(&packets, "PGP PUBLIC KEY BLOCK"))
}
