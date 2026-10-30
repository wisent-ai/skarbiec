//! Skarbiec's own format for an item: sealed to one or more X25519 keys
//! with ChaCha20-Poly1305, as README.md ("The sealed format") lays out.

use crate::chacha;
use crate::hmac::hkdf_sha256;
use crate::sha::sha256;
use crate::wipe::{wipe, Secret};
use crate::x25519;

/// The bytes every sealed item starts with.
pub const MAGIC: &[u8] = b"skarbiec-sealed-1\0";
const WRAP_INFO: &[u8] = b"skarbiec-sealed-1 wrap";
const RECIPIENT_LEN: usize = 8 + 32 + 32 + 16;

/// The identifier a sealed item names a recipient by: the first 8 bytes of
/// SHA-256 over its X25519 public key.
pub fn key_id(public: &[u8; 32]) -> [u8; 8] {
    let digest = sha256(public);
    digest[..8].try_into().expect("8 bytes")
}

/// Why a sealed item did not open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    NotSealed,
    Malformed(String),
    /// None of the keys held here is a recipient; the recipients' key ids.
    NoKey(Vec<String>),
    /// A recipient's wrapped key or the content fails its tag.
    Forged,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSealed => write!(formatter, "the data is not a Skarbiec sealed item"),
            Self::Malformed(why) => write!(formatter, "the sealed item is malformed: {why}"),
            Self::NoKey(ids) => write!(
                formatter,
                "no key held here is a recipient of this sealed item; it is sealed to key id(s) {}",
                ids.join(", ")
            ),
            Self::Forged => write!(
                formatter,
                "the sealed item does not authenticate: it was changed, or the key held here is not the one it names"
            ),
        }
    }
}

impl std::error::Error for OpenError {}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Seal `plaintext` to every key in `recipients`.
pub fn seal(recipients: &[[u8; 32]], plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
    if recipients.is_empty() || recipients.len() > 255 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "a sealed item has 1 to 255 recipients, not {}",
                recipients.len()
            ),
        ));
    }
    let mut content_key = crate::random::key()?;
    let mut out = MAGIC.to_vec();
    out.push(recipients.len() as u8);
    for public in recipients {
        let mut ephemeral = crate::random::key()?;
        let ephemeral_public = x25519::public_key(&ephemeral);
        let mut shared = x25519::shared_secret(&ephemeral, public).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a recipient key is of small order",
            )
        })?;
        let mut salt = ephemeral_public.to_vec();
        salt.extend_from_slice(public);
        let mut wrapping =
            hkdf_sha256(&salt, &shared, WRAP_INFO, 32).expect("32 bytes is within HKDF's limit");
        let wrapping_key: [u8; 32] = wrapping.as_slice().try_into().expect("32");
        out.extend_from_slice(&key_id(public));
        out.extend_from_slice(&ephemeral_public);
        out.extend(chacha::seal(&wrapping_key, &[0u8; 12], &[], &content_key));
        wipe(&mut ephemeral);
        wipe(&mut shared);
        wipe(&mut wrapping);
    }
    let nonce: [u8; 12] = crate::random::bytes(12)?.try_into().expect("12");
    let header = out.clone();
    out.extend_from_slice(&nonce);
    out.extend(chacha::seal(&content_key, &nonce, &header, plaintext));
    wipe(&mut content_key);
    Ok(out)
}

/// Whether `data` is a sealed item.
pub fn is_sealed(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

struct Parsed<'a> {
    header: &'a [u8],
    recipients: Vec<(&'a [u8], [u8; 32], &'a [u8])>,
    nonce: [u8; 12],
    body: &'a [u8],
}

fn parse(data: &[u8]) -> Result<Parsed<'_>, OpenError> {
    if !is_sealed(data) {
        return Err(OpenError::NotSealed);
    }
    let count = usize::from(
        *data
            .get(MAGIC.len())
            .ok_or_else(|| OpenError::Malformed("it has no recipient count".into()))?,
    );
    let header_end = MAGIC.len() + 1 + count * RECIPIENT_LEN;
    if count == 0 || data.len() < header_end + 12 + 16 {
        return Err(OpenError::Malformed(
            "it is shorter than its recipients, nonce and tag".into(),
        ));
    }
    let recipients = (0..count)
        .map(|i| {
            let at = MAGIC.len() + 1 + i * RECIPIENT_LEN;
            let id = &data[at..at + 8];
            let ephemeral: [u8; 32] = data[at + 8..at + 40].try_into().expect("32");
            (id, ephemeral, &data[at + 40..at + RECIPIENT_LEN])
        })
        .collect();
    Ok(Parsed {
        header: &data[..header_end],
        recipients,
        nonce: data[header_end..header_end + 12].try_into().expect("12"),
        body: &data[header_end + 12..],
    })
}

/// The key ids a sealed item is for, upper-case hex.
pub fn recipients(data: &[u8]) -> Result<Vec<String>, OpenError> {
    Ok(parse(data)?
        .recipients
        .iter()
        .map(|(id, _, _)| hex(id))
        .collect())
}

/// Open `data` with whichever of `secrets` (X25519 scalars) it is sealed to.
/// Every entry naming a held key is tried before the item is called forged:
/// an entry that does not unwrap (a key-id collision, or one put before the
/// genuine entry) does not hide the one that does.
pub fn open(data: &[u8], secrets: &[[u8; 32]]) -> Result<Secret, OpenError> {
    let parsed = parse(data)?;
    let mut matched = false;
    for secret in secrets {
        let public = x25519::public_key(secret);
        let id = key_id(&public);
        for (_, ephemeral, wrapped) in parsed.recipients.iter().filter(|(rid, _, _)| *rid == id) {
            matched = true;
            let Some(mut shared) = x25519::shared_secret(secret, ephemeral) else {
                continue;
            };
            let mut salt = ephemeral.to_vec();
            salt.extend_from_slice(&public);
            let mut wrapping = hkdf_sha256(&salt, &shared, WRAP_INFO, 32).expect("32 bytes");
            let mut wrapping_key: [u8; 32] = wrapping.as_slice().try_into().expect("32");
            wipe(&mut shared);
            wipe(&mut wrapping);
            let unwrapped = chacha::open(&wrapping_key, &[0u8; 12], &[], wrapped);
            wipe(&mut wrapping_key);
            let Ok(mut content) = unwrapped else {
                continue;
            };
            let Ok(mut content_key) = <[u8; 32]>::try_from(content.as_slice()) else {
                wipe(&mut content);
                continue;
            };
            wipe(&mut content);
            let opened = chacha::open(&content_key, &parsed.nonce, parsed.header, parsed.body);
            wipe(&mut content_key);
            match opened {
                Ok(plain) => return Ok(Secret::new(plain)),
                Err(_) => continue,
            }
        }
    }
    if matched {
        return Err(OpenError::Forged);
    }
    Err(OpenError::NoKey(
        parsed.recipients.iter().map(|(id, _, _)| hex(id)).collect(),
    ))
}
