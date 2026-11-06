//! OpenPGP v4 keys of the shape Skarbiec uses: an EdDSA (Ed25519) primary
//! key that certifies and signs, and an ECDH (Curve25519) subkey that
//! encrypts (RFC 4880 section 5.5, RFC 6637, RFC 9580 section 5.5.5 for the
//! legacy EdDSA and ECDH encodings). Reading parses transferable public keys
//! as gpg exports them; writing makes one, self-signed, that gpg imports.

use super::{hex_upper, malformed, packets, write_mpi, write_packet, Error, Reader};
use crate::sha::{sha1, Digest, Sha512};

/// The OID of Ed25519 in legacy EdDSA keys (algorithm 22).
pub const ED25519_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
/// The OID of Curve25519 in legacy ECDH keys (algorithm 18).
pub const CURVE25519_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
pub const ALGO_ECDH: u8 = 18;
pub const ALGO_EDDSA: u8 = 22;
/// SHA-256 and AES-128 as the ECDH key derivation's hash and key wrap
/// cipher (RFC 6637 section 9): what gpg writes for Curve25519.
pub const KDF_SHA256_AES128: [u8; 3] = [0x01, 0x08, 0x07];

/// An encryption subkey: Curve25519 ECDH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionKey {
    pub fingerprint: [u8; 20],
    pub created: u32,
    /// The X25519 public key (the native u-coordinate).
    pub x25519: [u8; 32],
    /// Hash and key wrap cipher of the ECDH key derivation.
    pub kdf_hash: u8,
    pub kdf_cipher: u8,
    /// The public key packet's body, as hashed into binding signatures.
    pub body: Vec<u8>,
}

impl EncryptionKey {
    pub fn key_id(&self) -> String {
        hex_upper(&self.fingerprint[12..])
    }
}

/// A transferable public key: the Ed25519 primary key, its user ids, its
/// Curve25519 subkeys, and what its self-signatures say of its lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub fingerprint: [u8; 20],
    pub created: u32,
    pub ed25519: [u8; 32],
    pub user_ids: Vec<String>,
    pub subkeys: Vec<EncryptionKey>,
    /// Seconds after creation the key expires, when a self-signature says.
    pub expires_after: Option<u32>,
    pub revoked: bool,
    /// The primary public key packet's body.
    pub body: Vec<u8>,
}

impl PublicKey {
    pub fn fingerprint_hex(&self) -> String {
        hex_upper(&self.fingerprint)
    }

    pub fn key_id(&self) -> String {
        hex_upper(&self.fingerprint[12..])
    }
}

/// The v4 fingerprint of a public key packet body (RFC 4880 section 12.2).
pub fn fingerprint(body: &[u8]) -> [u8; 20] {
    let mut framed = vec![0x99];
    framed.extend_from_slice(&(body.len() as u16).to_be_bytes());
    framed.extend_from_slice(body);
    sha1(&framed)
}

/// The 32 bytes of a native-point MPI `0x40 || x` (RFC 9580 section 5.5.5.5).
fn native_point(mpi: &[u8], what: &str) -> Result<[u8; 32], Error> {
    match mpi {
        [0x40, rest @ ..] if rest.len() == 32 => Ok(rest.try_into().expect("32 bytes")),
        _ => Err(malformed(format!(
            "{what} is not a 0x40-prefixed 32-byte point"
        ))),
    }
}

enum Parsed {
    Signing([u8; 32]),
    Encryption([u8; 32], u8, u8),
}

fn parse_key_body(body: &[u8]) -> Result<(u32, Parsed), Error> {
    let mut r = Reader::new(body);
    let version = r.byte("a key version")?;
    if version != 4 {
        return Err(Error::Unsupported(format!("a version {version} key")));
    }
    let created = r.u32("a key creation time")?;
    let algo = r.byte("a key algorithm")?;
    let oid_len = usize::from(r.byte("a curve OID length")?);
    let oid = r.take(oid_len, "a curve OID")?;
    let point = r.mpi("a public point")?;
    match (algo, oid) {
        (ALGO_EDDSA, ED25519_OID) => Ok((
            created,
            Parsed::Signing(native_point(point, "the Ed25519 key")?),
        )),
        (ALGO_ECDH, CURVE25519_OID) => {
            let kdf_len = r.byte("ECDH KDF parameters")?;
            let kdf = r.take(usize::from(kdf_len), "ECDH KDF parameters")?;
            if kdf.len() != 3 || kdf[0] != 1 {
                return Err(Error::Unsupported(
                    "ECDH KDF parameters other than version 1".into(),
                ));
            }
            Ok((
                created,
                Parsed::Encryption(native_point(point, "the Curve25519 key")?, kdf[1], kdf[2]),
            ))
        }
        _ => Err(Error::Unsupported(format!(
            "public key algorithm {algo} on curve OID {}",
            hex_upper(oid)
        ))),
    }
}

/// One signature subpacket: its type and data.
pub(crate) type Subpacket = (u8, Vec<u8>);

/// The hashed subpackets of a v4 signature body, and the signature type.
fn hashed_subpackets(body: &[u8]) -> Result<(u8, Vec<Subpacket>), Error> {
    let mut r = Reader::new(body);
    if r.byte("a signature version")? != 4 {
        return Err(Error::Unsupported(
            "a signature that is not version 4".into(),
        ));
    }
    let kind = r.byte("a signature type")?;
    r.take(2, "signature algorithms")?;
    let len = usize::from(r.u16("hashed subpackets")?);
    let area = r.take(len, "hashed subpackets")?;
    Ok((kind, subpackets(area)?))
}

pub(crate) fn subpackets(area: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, Error> {
    let mut r = Reader::new(area);
    let mut out = Vec::new();
    while r.remaining() > 0 {
        let first = r.byte("a subpacket length")?;
        let len = match first {
            0..=191 => usize::from(first),
            192..=254 => {
                ((usize::from(first) - 192) << 8) + usize::from(r.byte("a subpacket length")?) + 192
            }
            255 => r.u32("a subpacket length")? as usize,
        };
        if len == 0 {
            return Err(malformed("a subpacket has length zero"));
        }
        let data = r.take(len, "a subpacket")?;
        out.push((data[0] & 0x7f, data[1..].to_vec()));
    }
    Ok(out)
}

/// Every transferable public key in `data` (binary packets).
pub fn parse_public_keys(data: &[u8]) -> Result<Vec<PublicKey>, Error> {
    let mut keys: Vec<PublicKey> = Vec::new();
    for packet in packets(data)? {
        match packet.tag {
            6 | 5 => {
                let body = if packet.tag == 5 {
                    public_part(&packet.body)?
                } else {
                    packet.body.clone()
                };
                let (created, parsed) = parse_key_body(&body)?;
                let Parsed::Signing(ed25519) = parsed else {
                    return Err(Error::Unsupported(
                        "a primary key that is not Ed25519".into(),
                    ));
                };
                keys.push(PublicKey {
                    fingerprint: fingerprint(&body),
                    created,
                    ed25519,
                    user_ids: Vec::new(),
                    subkeys: Vec::new(),
                    expires_after: None,
                    revoked: false,
                    body,
                });
            }
            13 => {
                let key = keys
                    .last_mut()
                    .ok_or_else(|| malformed("a user id before any key"))?;
                key.user_ids
                    .push(String::from_utf8_lossy(&packet.body).into_owned());
            }
            14 | 7 => {
                let key = keys
                    .last_mut()
                    .ok_or_else(|| malformed("a subkey before any key"))?;
                let body = if packet.tag == 7 {
                    public_part(&packet.body)?
                } else {
                    packet.body.clone()
                };
                let (created, parsed) = parse_key_body(&body)?;
                if let Parsed::Encryption(x25519, kdf_hash, kdf_cipher) = parsed {
                    key.subkeys.push(EncryptionKey {
                        fingerprint: fingerprint(&body),
                        created,
                        x25519,
                        kdf_hash,
                        kdf_cipher,
                        body,
                    });
                }
            }
            2 => {
                let Some(key) = keys.last_mut() else { continue };
                let Ok((kind, hashed)) = hashed_subpackets(&packet.body) else {
                    continue;
                };
                // Only signatures the key makes on itself and its user ids
                // speak for its lifetime; the latest one wins.
                match kind {
                    0x10..=0x13 | 0x1f if key.subkeys.is_empty() => {
                        if let Some((_, data)) = hashed.iter().find(|(t, _)| *t == 9) {
                            if data.len() == 4 {
                                key.expires_after =
                                    Some(u32::from_be_bytes(data[..4].try_into().expect("4")));
                            }
                        }
                    }
                    0x20 => key.revoked = true,
                    _ => {}
                }
            }
            _ => {}
        }
    }
    Ok(keys)
}

/// The public part of a secret key packet body: up to the end of its
/// public fields.
fn public_part(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(body);
    r.take(6, "a key header")?;
    let algo = body[5];
    let oid_len = usize::from(r.byte("a curve OID length")?);
    r.take(oid_len, "a curve OID")?;
    r.mpi("a public point")?;
    if algo == ALGO_ECDH {
        let n = usize::from(r.byte("ECDH KDF parameters")?);
        r.take(n, "ECDH KDF parameters")?;
    }
    Ok(body[..body.len() - r.remaining()].to_vec())
}

/// A v4 EdDSA public key packet body for `ed25519`.
pub fn ed25519_body(created: u32, ed25519: &[u8; 32]) -> Vec<u8> {
    let mut body = vec![4];
    body.extend_from_slice(&created.to_be_bytes());
    body.push(ALGO_EDDSA);
    body.push(ED25519_OID.len() as u8);
    body.extend_from_slice(ED25519_OID);
    let mut point = vec![0x40];
    point.extend_from_slice(ed25519);
    body.extend(write_mpi(&point));
    body
}

/// A v4 ECDH public key packet body for `x25519`, SHA-256 and AES-128.
pub fn x25519_body(created: u32, x25519: &[u8; 32]) -> Vec<u8> {
    let mut body = vec![4];
    body.extend_from_slice(&created.to_be_bytes());
    body.push(ALGO_ECDH);
    body.push(CURVE25519_OID.len() as u8);
    body.extend_from_slice(CURVE25519_OID);
    let mut point = vec![0x40];
    point.extend_from_slice(x25519);
    body.extend(write_mpi(&point));
    body.push(3);
    body.extend_from_slice(&KDF_SHA256_AES128);
    body
}

fn subpacket(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![(data.len() + 1) as u8, kind];
    out.extend_from_slice(data);
    out
}

/// A v4 EdDSA signature of `kind` over `hashed_data` (what precedes the
/// signature's own fields), made with `seed` as `fingerprint`.
pub(crate) fn sign_v4(
    seed: &[u8; 32],
    issuer: &[u8; 20],
    kind: u8,
    created: u32,
    extra: &[u8],
    hashed_data: &[u8],
) -> Vec<u8> {
    let mut hashed = subpacket(33, &[&[4u8][..], issuer].concat());
    hashed.extend(subpacket(2, &created.to_be_bytes()));
    hashed.extend_from_slice(extra);
    let mut header = vec![4, kind, ALGO_EDDSA, 10];
    header.extend_from_slice(&(hashed.len() as u16).to_be_bytes());
    header.extend_from_slice(&hashed);
    let mut trailer = vec![4, 0xff];
    trailer.extend_from_slice(&(header.len() as u32).to_be_bytes());
    let mut hash = Sha512::new();
    hash.update(hashed_data);
    hash.update(&header);
    hash.update(&trailer);
    let mut digest = [0u8; 64];
    hash.finish_into(&mut digest);
    let signature = crate::ed25519::sign(seed, &digest);
    let unhashed = subpacket(16, &issuer[12..]);
    let mut body = header;
    body.extend_from_slice(&(unhashed.len() as u16).to_be_bytes());
    body.extend_from_slice(&unhashed);
    body.extend_from_slice(&digest[..2]);
    body.extend(write_mpi(&signature[..32]));
    body.extend(write_mpi(&signature[32..]));
    body
}

fn key_frame(tag_byte: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag_byte];
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A transferable public key gpg imports: the Ed25519 primary key with
/// `user_id`, certified, and the Curve25519 subkey, bound; every signature
/// made with `seed`.
pub fn transferable_public_key(
    seed: &[u8; 32],
    x25519: &[u8; 32],
    user_id: &str,
    created: u32,
) -> Vec<u8> {
    let ed = crate::ed25519::public_key(seed);
    let primary = ed25519_body(created, &ed);
    let fpr = fingerprint(&primary);
    let sub = x25519_body(created, x25519);
    let mut uid_hash = key_frame(0x99, &primary);
    uid_hash.push(0xb4);
    uid_hash.extend_from_slice(&(user_id.len() as u32).to_be_bytes());
    uid_hash.extend_from_slice(user_id.as_bytes());
    // Key flags: certify and sign (0x03); preferences: AES-256, SHA-512, ZLIB.
    let mut certify_extra = subpacket(27, &[0x03]);
    certify_extra.extend(subpacket(11, &[9]));
    certify_extra.extend(subpacket(21, &[10]));
    certify_extra.extend(subpacket(22, &[2]));
    certify_extra.extend(subpacket(30, &[0x01]));
    let certification = sign_v4(seed, &fpr, 0x13, created, &certify_extra, &uid_hash);
    let mut bind_hash = key_frame(0x99, &primary);
    bind_hash.extend(key_frame(0x99, &sub));
    // Key flags: encrypt communications and storage (0x0c).
    let binding = sign_v4(
        seed,
        &fpr,
        0x18,
        created,
        &subpacket(27, &[0x0c]),
        &bind_hash,
    );
    let mut out = write_packet(6, &primary);
    out.extend(write_packet(13, user_id.as_bytes()));
    out.extend(write_packet(2, &certification));
    out.extend(write_packet(14, &sub));
    out.extend(write_packet(2, &binding));
    out
}

/// Whether `key`'s self-signatures verify: each user id's certification and
/// each subkey's binding, with the primary key. A key whose binding does not
/// verify is not this key's, whatever its packets say.
pub fn verify_self_signatures(data: &[u8]) -> Result<(), Error> {
    let mut primary: Option<(Vec<u8>, [u8; 32], [u8; 20])> = None;
    let mut uid: Option<Vec<u8>> = None;
    let mut sub: Option<Vec<u8>> = None;
    // A user attribute (a photo id) is bound by signatures over itself,
    // which say nothing of the user ids and subkey this reads.
    let mut attribute = false;
    let mut verified = 0;
    for packet in packets(data)? {
        match packet.tag {
            6 => {
                let (_, parsed) = parse_key_body(&packet.body)?;
                let Parsed::Signing(ed) = parsed else {
                    return Err(Error::Unsupported(
                        "a primary key that is not Ed25519".into(),
                    ));
                };
                primary = Some((packet.body.clone(), ed, fingerprint(&packet.body)));
                uid = None;
                sub = None;
                attribute = false;
            }
            13 => {
                uid = Some(packet.body.clone());
                sub = None;
                attribute = false;
            }
            17 => attribute = true,
            14 => {
                sub = Some(packet.body.clone());
                attribute = false;
            }
            2 if !attribute => {
                let (body, ed, fpr) = primary
                    .as_ref()
                    .ok_or_else(|| malformed("a signature before any key"))?;
                // Another key's certification of a user id is that key's
                // statement, not this key's own; it is not checked here.
                if !fpr.ends_with(&super::signature::issuer(&packet.body)?) {
                    continue;
                }
                let mut hashed = key_frame(0x99, body);
                match (&sub, &uid) {
                    (Some(sub), _) => hashed.extend(key_frame(0x99, sub)),
                    (None, Some(uid)) => {
                        hashed.push(0xb4);
                        hashed.extend_from_slice(&(uid.len() as u32).to_be_bytes());
                        hashed.extend_from_slice(uid);
                    }
                    (None, None) => {}
                }
                super::signature::verify_v4(ed, &packet.body, &hashed)?;
                verified += 1;
            }
            _ => {}
        }
    }
    if verified == 0 {
        return Err(Error::BadSignature(
            "the key carries no self-signature".into(),
        ));
    }
    Ok(())
}
