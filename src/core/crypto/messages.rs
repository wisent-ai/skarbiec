// What the vault does with a message: seal it to recipients, open it with
// the keys this host holds, sign it, and hash it. Every step runs in this
// process, on skarbiec-crypto; nothing waits on another program.

use anyhow::{bail, Context, Result};

use skarbiec_crypto::openpgp::armor::{armor, dearmor};
use skarbiec_crypto::openpgp::message::DecryptionKey;
use skarbiec_crypto::sealed;
use skarbiec_crypto::wipe::Secret;

use super::keyring::{self, Keyring};

/// The armor kind an item sealed in Skarbiec's own format is written in.
pub(crate) const SEALED_KIND: &str = "SKARBIEC SEALED";
const SEALED_BEGIN: &str = "-----BEGIN SKARBIEC SEALED-----";
const OPENPGP_BEGIN: &str = "-----BEGIN PGP MESSAGE-----";

/// Which format a stored ciphertext is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Skarbiec's own sealed format, what every write now produces.
    Sealed,
    /// An OpenPGP message, what gpg wrote before; read, never written.
    OpenPgp,
}

/// The format `ciphertext` is in, refused naming what it starts with.
pub fn format_of(ciphertext: &str) -> Result<Format> {
    let text = ciphertext.trim_start();
    if text.starts_with(SEALED_BEGIN) {
        return Ok(Format::Sealed);
    }
    if text.starts_with(OPENPGP_BEGIN) {
        return Ok(Format::OpenPgp);
    }
    let start: String = text.chars().take(40).collect();
    bail!(
        "the ciphertext is neither a Skarbiec sealed item ({SEALED_BEGIN}) nor an OpenPGP message \
         ({OPENPGP_BEGIN}); it starts {start:?}, so it was damaged or is not a vault ciphertext"
    )
}

pub fn clearsign(signer: &str, payload: &str) -> Result<String> {
    let keyring = keyring::load()?;
    let key = keyring.find(signer).with_context(|| {
        format!(
            "the key file {} holds no key for {signer} to sign with",
            keyring.path.display()
        )
    })?;
    let secret = key.secret(&keyring.path)?;
    let seed: [u8; 32] = secret
        .seed
        .expose()
        .try_into()
        .context("an Ed25519 seed is 32 bytes")?;
    let created = u32::try_from(crate::core::clock::epoch_seconds()?)
        .context("the clock is past what an OpenPGP signature can state (2106)")?;
    Ok(skarbiec_crypto::openpgp::signature::sign_cleartext(
        &seed,
        &key.public.body,
        payload,
        created,
    ))
}

/// The text a cleartext-signed message carries, when its signature verifies
/// with a key in this host's key file.
pub fn verify_clearsigned(signed: &str) -> Result<String> {
    let keyring = keyring::load()?;
    let keys: Vec<_> = keyring.keys.iter().map(|key| key.public.clone()).collect();
    skarbiec_crypto::openpgp::signature::verify_cleartext(signed, &keys).map_err(|error| {
        anyhow::anyhow!(
            "the signed checkpoint does not verify with the keys in {}: {error}",
            keyring.path.display()
        )
    })
}

/// The bytes of entropy in a consumer service token, which so carries 256
/// bits, above the 2^-160 guessing bound RFC 6749 sets for access tokens,
/// https://www.rfc-editor.org/rfc/rfc6749#section-10.10
const TOKEN_BYTES: usize = 32;

/// High-entropy random token (hex). Used for consumer service tokens.
pub fn random_token() -> Result<String> {
    let bytes = skarbiec_crypto::random::bytes(TOKEN_BYTES)
        .context("draw the random bytes of a service token")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Hex SHA-256 of the input: the audit chain, bearer verification, the
/// payload fingerprints.
pub fn sha256_hex(input: &str) -> Result<String> {
    Ok(sha256_hex_bytes(input.as_bytes()))
}

/// Hex SHA-256 of bytes.
pub fn sha256_hex_bytes(input: &[u8]) -> String {
    skarbiec_crypto::sha::sha256(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// SHA-1 (uppercase hex) — required only for the HaveIBeenPwned range API, which
/// is defined over SHA-1 password hashes. Not used for any security decision.
pub fn sha1_hex_upper(input: &str) -> Result<String> {
    Ok(skarbiec_crypto::sha::sha1(input.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect())
}

/// Seal plaintext to every recipient's key: any one of them (or the recovery
/// key) opens it. A fingerprint the key file does not hold is refused naming
/// it, so an item is never sealed to fewer people than asked.
pub fn encrypt_to(recipients: &[String], plaintext: &str) -> Result<String> {
    if recipients.is_empty() {
        bail!("refusing to encrypt with no recipients");
    }
    let keyring = keyring::load()?;
    seal_with(&keyring, recipients, plaintext.as_bytes())
}

pub(crate) fn seal_with(
    keyring: &Keyring,
    recipients: &[String],
    plaintext: &[u8],
) -> Result<String> {
    let now = crate::core::clock::epoch_seconds()?;
    let mut publics = Vec::with_capacity(recipients.len());
    for fingerprint in recipients {
        let key = keyring.require(fingerprint)?;
        // A revoked or expired key is one its holder said no longer to
        // write to; sealing to it anyway would hide the change from them.
        if key.public.revoked {
            bail!(
                "key {fingerprint} is revoked, so nothing new is sealed to it; give its holder a \
                 new key (`skarbiec recipient rekey`, or `skarbiec owner rotate` for the owner)"
            );
        }
        if let Some(after) = key.public.expires_after.filter(|after| *after != 0) {
            if u64::from(key.public.created) + u64::from(after) <= now {
                bail!(
                    "key {fingerprint} expired, so nothing new is sealed to it; `skarbiec keys` \
                     names the repair: re-sign it with a later expiry and import it again, or give \
                     its holder a new key"
                );
            }
        }
        let x25519 = key.x25519()?;
        if !publics.contains(&x25519) {
            publics.push(x25519);
        }
    }
    let sealed = sealed::seal(&publics, plaintext).context("seal the item")?;
    Ok(armor(&sealed, SEALED_KIND))
}

/// Seal plaintext with a passphrase instead of a key, as an armored OpenPGP
/// message: for a person outside the vault, who opens it with any OpenPGP
/// tool and the phrase handed over another way.
pub fn seal_with_passphrase(phrase: &str, plaintext: &str) -> Result<String> {
    let message = skarbiec_crypto::openpgp::message::seal_with_passphrase(
        phrase.as_bytes(),
        plaintext.as_bytes(),
    )
    .context("seal the message with its passphrase")?;
    Ok(armor(&message, "PGP MESSAGE"))
}

/// Open a stored ciphertext with the secret keys this host holds: a sealed
/// item, or an OpenPGP message gpg wrote before.
pub fn decrypt(ciphertext: &str) -> Result<String> {
    let keyring = keyring::load()?;
    let opened = open_with(&keyring, ciphertext)?;
    String::from_utf8(opened.into_inner()).context("the opened item is not UTF-8 text")
}

pub(crate) fn open_with(keyring: &Keyring, ciphertext: &str) -> Result<Secret> {
    let (held, locked) = keyring.secrets();
    let locked_note = if locked.is_empty() {
        String::new()
    } else {
        format!("; keys this host could not unlock: {}", locked.join("; "))
    };
    match format_of(ciphertext)? {
        Format::Sealed => {
            let data = dearmor(ciphertext, SEALED_KIND)
                .map_err(|error| anyhow::anyhow!("the sealed item's armor: {error}"))?;
            let scalars: Vec<[u8; 32]> = held
                .iter()
                .filter_map(|(_, half)| half.scalar.expose().try_into().ok())
                .collect();
            sealed::open(&data, &scalars).map_err(|error| match error {
                sealed::OpenError::NoKey(_) => anyhow::anyhow!(
                    "{error}; the key file {} holds the secret half of {} key(s), none of them a \
                     recipient: import the recipient's key here (`skarbiec keys import`){locked_note}",
                    keyring.path.display(),
                    held.len()
                ),
                other => anyhow::anyhow!("{other}{locked_note}"),
            })
        }
        Format::OpenPgp => {
            let data = dearmor(ciphertext, "PGP MESSAGE")
                .map_err(|error| anyhow::anyhow!("the OpenPGP message's armor: {error}"))?;
            let mut keys = Vec::new();
            for (key, half) in &held {
                let Ok(scalar) = <[u8; 32]>::try_from(half.scalar.expose()) else {
                    continue;
                };
                let public = skarbiec_crypto::x25519::public_key(&scalar);
                for subkey in key.public.subkeys.iter().filter(|sub| sub.x25519 == public) {
                    keys.push(DecryptionKey {
                        subkey_body: subkey.body.clone(),
                        scalar: half.scalar.clone(),
                    });
                }
            }
            skarbiec_crypto::openpgp::message::decrypt(&data, &keys).map_err(|error| match error {
                skarbiec_crypto::openpgp::Error::NoKey(_) => anyhow::anyhow!(
                    "{error}; the key file {} holds the secret half of {} key(s), none of them a \
                     recipient: import the recipient's key here (`skarbiec keys import`){locked_note}",
                    keyring.path.display(),
                    held.len()
                ),
                other => anyhow::anyhow!("{other}{locked_note}"),
            })
        }
    }
}

/// The key ids a ciphertext is sealed to, read without opening it: for a
/// sealed item the first 8 bytes of SHA-256 over each X25519 key, for an
/// OpenPGP message each encryption subkey's key id.
pub fn encrypted_to(ciphertext: &str) -> Result<Vec<String>> {
    match format_of(ciphertext)? {
        Format::Sealed => {
            let data = dearmor(ciphertext, SEALED_KIND)
                .map_err(|error| anyhow::anyhow!("the sealed item's armor: {error}"))?;
            sealed::recipients(&data).map_err(|error| anyhow::anyhow!("{error}"))
        }
        Format::OpenPgp => {
            let data = dearmor(ciphertext, "PGP MESSAGE")
                .map_err(|error| anyhow::anyhow!("the OpenPGP message's armor: {error}"))?;
            skarbiec_crypto::openpgp::message::recipients(&data)
                .map_err(|error| anyhow::anyhow!("{error}"))
        }
    }
}

/// Whether the key file holds a secret half a ciphertext's recipient `key_id`
/// (as [`encrypted_to`] names it) belongs to, and that key's fingerprint.
pub fn holder_of(key_id: &str) -> Result<Option<(String, bool)>> {
    let keyring = keyring::load()?;
    for key in &keyring.keys {
        for subkey in &key.public.subkeys {
            let sealed_id: String = sealed::key_id(&subkey.x25519)
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect();
            if sealed_id == key_id || subkey.key_id() == key_id {
                return Ok(Some((key.fingerprint(), key.holds_secret())));
            }
        }
    }
    Ok(None)
}
