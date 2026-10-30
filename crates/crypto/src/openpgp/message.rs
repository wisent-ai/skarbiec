//! OpenPGP messages: opening ones encrypted to a Curve25519 ECDH key (RFC
//! 6637) or sealed with a passphrase, whose data is AES in OCB (LibrePGP's
//! OCB encrypted data packet) or in CFB with a modification detection code
//! (RFC 4880 sections 5.13 and 5.14); and writing a passphrase-sealed
//! message any OpenPGP implementation opens.

use super::agent::s2k_iterated;
use super::keys::{fingerprint, ALGO_ECDH, CURVE25519_OID};
use super::{hex_upper, malformed, packets, write_packet, Error, Packet, Reader};
use crate::aes::{cfb_decrypt, cfb_encrypt, key_unwrap, Aes};
use crate::ocb::Ocb;
use crate::sha::{sha1, Sha1, Sha256, Sha512};
use crate::wipe::{equal, wipe, Secret};

/// A Curve25519 secret held here: the subkey packet body it belongs to
/// (for its fingerprint and KDF parameters) and the native X25519 scalar.
pub struct DecryptionKey {
    pub subkey_body: Vec<u8>,
    pub scalar: Secret,
}

impl DecryptionKey {
    pub fn key_id(&self) -> String {
        hex_upper(&fingerprint(&self.subkey_body)[12..])
    }
}

/// The key ids a message's public-key session packets are for.
pub fn recipients(message: &[u8]) -> Result<Vec<String>, Error> {
    Ok(packets(message)?
        .iter()
        .filter(|p| p.tag == 1 && p.body.len() >= 9)
        .map(|p| hex_upper(&p.body[1..9]))
        .collect())
}

fn key_len(cipher: u8) -> Result<usize, Error> {
    match cipher {
        7 => Ok(16),
        8 => Ok(24),
        9 => Ok(32),
        other => Err(Error::Unsupported(format!("symmetric cipher {other}"))),
    }
}

/// The session key in a v3 ECDH session key packet, opened with `key`.
fn open_pkesk(body: &[u8], key: &DecryptionKey) -> Result<(u8, Secret), Error> {
    let mut r = Reader::new(body);
    if r.byte("a session key packet version")? != 3 {
        return Err(Error::Unsupported(
            "a session key packet that is not version 3".into(),
        ));
    }
    r.take(8, "a key id")?;
    let algo = r.byte("a public key algorithm")?;
    if algo != ALGO_ECDH {
        return Err(Error::Unsupported(format!(
            "session keys encrypted with algorithm {algo}"
        )));
    }
    let ephemeral = match r.mpi("the ephemeral key")? {
        [0x40, rest @ ..] if rest.len() == 32 => <[u8; 32]>::try_from(rest).expect("32"),
        _ => return Err(malformed("the ephemeral key is not a 0x40-prefixed point")),
    };
    let wrapped_len = usize::from(r.byte("the wrapped key length")?);
    let wrapped = r.take(wrapped_len, "the wrapped key")?;
    // The subkey's KDF parameters: its body ends 03 01 <hash> <cipher>.
    let sub = &key.subkey_body;
    let (kdf_hash, kdf_cipher) = (sub[sub.len() - 2], sub[sub.len() - 1]);
    let scalar: [u8; 32] = key
        .scalar
        .expose()
        .try_into()
        .map_err(|_| malformed("an X25519 secret is not 32 bytes"))?;
    let mut shared = crate::x25519::shared_secret(&scalar, &ephemeral)
        .ok_or_else(|| Error::Integrity("the sender's ephemeral key is of small order".into()))?;
    let mut param = vec![CURVE25519_OID.len() as u8];
    param.extend_from_slice(CURVE25519_OID);
    param.push(ALGO_ECDH);
    param.extend_from_slice(&[3, 1, kdf_hash, kdf_cipher]);
    param.extend_from_slice(b"Anonymous Sender    ");
    param.extend_from_slice(&fingerprint(sub));
    let mut kdf_input = vec![0, 0, 0, 1];
    kdf_input.extend_from_slice(&shared);
    kdf_input.extend_from_slice(&param);
    let mut digest = match kdf_hash {
        8 => crate::sha::sha256(&kdf_input).to_vec(),
        10 => crate::sha::sha512(&kdf_input).to_vec(),
        other => return Err(Error::Unsupported(format!("ECDH KDF hash {other}"))),
    };
    let kek_len = key_len(kdf_cipher)?;
    let kek = Aes::new(&digest[..kek_len]).map_err(|e| malformed(e.to_string()))?;
    wipe(&mut digest);
    wipe(&mut kdf_input);
    wipe(&mut shared);
    let mut m = key_unwrap(&kek, wrapped).ok_or_else(|| {
        Error::Integrity("the session key does not unwrap with this key: it is not encrypted to it, or it was changed".into())
    })?;
    let session = parse_session(&mut m, true)?;
    wipe(&mut m);
    Ok(session)
}

/// `algo || key || checksum`, padded (RFC 6637) when `padded`.
fn parse_session(m: &mut Vec<u8>, padded: bool) -> Result<(u8, Secret), Error> {
    if padded {
        let pad = usize::from(
            *m.last()
                .ok_or_else(|| malformed("the session key is empty"))?,
        );
        if pad == 0 || pad > m.len() || !m[m.len() - pad..].iter().all(|&b| usize::from(b) == pad) {
            return Err(Error::Integrity(
                "the session key's padding is wrong".into(),
            ));
        }
        m.truncate(m.len() - pad);
    }
    if m.len() < 3 {
        return Err(malformed("the session key is too short"));
    }
    let cipher = m[0];
    let key = &m[1..m.len() - 2];
    if key.len() != key_len(cipher)? {
        return Err(malformed(
            "the session key's length does not fit its cipher",
        ));
    }
    let checksum = key
        .iter()
        .fold(0u16, |sum, &b| sum.wrapping_add(u16::from(b)));
    if checksum.to_be_bytes() != m[m.len() - 2..] {
        return Err(Error::Integrity(
            "the session key's checksum is wrong".into(),
        ));
    }
    Ok((cipher, Secret::new(key.to_vec())))
}

/// Decrypt an OCB encrypted data packet body (LibrePGP section 5.16) with
/// its session key.
pub fn open_ocb_packet(body: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(body);
    let version = r.byte("the AEAD packet version")?;
    let cipher = r.byte("the AEAD cipher")?;
    let mode = r.byte("the AEAD mode")?;
    let chunk_byte = r.byte("the AEAD chunk size")?;
    if version != 1 || mode != 2 {
        return Err(Error::Unsupported(format!(
            "an AEAD packet of version {version} and mode {mode}"
        )));
    }
    if key.len() != key_len(cipher)? {
        return Err(malformed("the session key does not fit the data's cipher"));
    }
    if chunk_byte > 16 {
        return Err(malformed(
            "the AEAD chunk size is above the 4 MiB the format allows",
        ));
    }
    let iv: [u8; 15] = r.take(15, "the AEAD IV")?.try_into().expect("15");
    let rest = r.rest();
    if rest.len() < 16 {
        return Err(malformed("the AEAD data has no final tag"));
    }
    let (chunks, final_tag) = rest.split_at(rest.len() - 16);
    let chunk_size = 1usize << (chunk_byte + 6);
    let aes = Aes::new(key).map_err(|e| malformed(e.to_string()))?;
    let ocb = Ocb::new(&aes, 16).map_err(|e| malformed(e.to_string()))?;
    let header = [0xd4, version, cipher, mode, chunk_byte];
    let nonce_at = |index: u64| {
        let mut nonce = iv;
        for (n, b) in nonce[7..].iter_mut().zip(index.to_be_bytes()) {
            *n ^= b;
        }
        nonce
    };
    let mut out = Vec::with_capacity(chunks.len());
    let mut index = 0u64;
    for chunk in chunks.chunks(chunk_size + 16) {
        let mut aad = header.to_vec();
        aad.extend_from_slice(&index.to_be_bytes());
        let plain = ocb
            .open(&nonce_at(index), &aad, chunk)
            .map_err(|_| Error::Integrity(format!("AEAD chunk {index} does not authenticate: the data was changed or this is not its key")))?;
        out.extend_from_slice(&plain);
        index += 1;
    }
    let mut aad = header.to_vec();
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&(out.len() as u64).to_be_bytes());
    ocb.open(&nonce_at(index), &aad, final_tag).map_err(|_| {
        Error::Integrity(
            "the AEAD final tag does not authenticate: the data was cut short or changed".into(),
        )
    })?;
    Ok(out)
}

/// Decrypt a symmetrically encrypted integrity protected data packet body
/// (RFC 4880 section 5.13), checking its modification detection code.
fn open_seipd(body: &[u8], cipher: u8, key: &[u8]) -> Result<Vec<u8>, Error> {
    let (&version, data) = body
        .split_first()
        .ok_or_else(|| malformed("the encrypted data packet is empty"))?;
    if version != 1 {
        return Err(Error::Unsupported(format!(
            "an encrypted data packet of version {version}"
        )));
    }
    if key.len() != key_len(cipher)? {
        return Err(malformed("the session key does not fit its cipher"));
    }
    if data.len() < 18 + 22 {
        return Err(malformed(
            "the encrypted data is shorter than its prefix and check",
        ));
    }
    let aes = Aes::new(key).map_err(|e| malformed(e.to_string()))?;
    let mut clear = data.to_vec();
    cfb_decrypt(&aes, &[0u8; 16], &mut clear);
    let mdc_at = clear.len() - 22;
    let expected = sha1(&clear[..mdc_at + 2]);
    let intact =
        clear[mdc_at..mdc_at + 2] == [0xd3, 0x14] && equal(&expected, &clear[mdc_at + 2..]);
    if !intact {
        wipe(&mut clear);
        return Err(Error::Integrity("the modification detection code does not match: the data was changed or this is not its key".into()));
    }
    let out = clear[18..mdc_at].to_vec();
    wipe(&mut clear);
    Ok(out)
}

/// The literal data inside decrypted packets, through compression.
fn literal(decrypted: &[u8]) -> Result<Vec<u8>, Error> {
    for packet in packets(decrypted)? {
        match packet.tag {
            8 => {
                let (&algo, data) = packet
                    .body
                    .split_first()
                    .ok_or_else(|| malformed("the compressed packet is empty"))?;
                let inner = match algo {
                    0 => data.to_vec(),
                    1 => {
                        crate::inflate::inflate(data)
                            .map_err(|e| malformed(e.to_string()))?
                            .0
                    }
                    2 => crate::inflate::zlib_decompress(data)
                        .map_err(|e| malformed(e.to_string()))?,
                    other => {
                        return Err(Error::Unsupported(format!("compression algorithm {other}")))
                    }
                };
                return literal(&inner);
            }
            11 => {
                let mut r = Reader::new(&packet.body);
                r.byte("the literal data format")?;
                let name_len = usize::from(r.byte("the literal file name length")?);
                r.take(name_len, "the literal file name")?;
                r.take(4, "the literal date")?;
                return Ok(r.rest().to_vec());
            }
            4 | 2 | 10 => {}
            other => {
                return Err(Error::Unsupported(format!(
                    "a packet of type {other} inside the encrypted data"
                )))
            }
        }
    }
    Err(malformed("the encrypted data holds no literal data"))
}

fn open_data(data_packets: &[Packet], cipher: Option<u8>, key: &[u8]) -> Result<Vec<u8>, Error> {
    let data = data_packets
        .iter()
        .find(|p| matches!(p.tag, 18 | 20 | 9))
        .ok_or_else(|| malformed("the message holds no encrypted data"))?;
    let mut decrypted = match (data.tag, cipher) {
        (20, _) => open_ocb_packet(&data.body, key)?,
        (18, Some(cipher)) => open_seipd(&data.body, cipher, key)?,
        (18, None) => return Err(malformed("the session key names no cipher for its data")),
        _ => {
            return Err(Error::Unsupported(
                "symmetrically encrypted data without integrity protection".into(),
            ))
        }
    };
    let out = literal(&decrypted);
    wipe(&mut decrypted);
    out
}

/// Open `message` (binary packets) with whichever of `keys` it is
/// encrypted to.
pub fn decrypt(message: &[u8], keys: &[DecryptionKey]) -> Result<Secret, Error> {
    let all = packets(message)?;
    let sessions: Vec<&Packet> = all.iter().filter(|p| p.tag == 1).collect();
    if sessions.is_empty() {
        return Err(malformed("the message is encrypted to no public key"));
    }
    let mut last_error = None;
    for session in &sessions {
        let id = &session
            .body
            .get(1..9)
            .ok_or_else(|| malformed("a session key packet is cut short"))?;
        for key in keys
            .iter()
            .filter(|k| fingerprint(&k.subkey_body)[12..] == **id)
        {
            match open_pkesk(&session.body, key) {
                Ok((cipher, session_key)) => {
                    return open_data(&all, Some(cipher), session_key.expose()).map(Secret::new)
                }
                Err(error) => last_error = Some(error),
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        Error::NoKey(sessions.iter().map(|s| hex_upper(&s.body[1..9])).collect())
    }))
}

fn s2k_count(c: u8) -> u64 {
    (16 + u64::from(c & 15)) << ((c >> 4) + 6)
}

fn s2k(
    hash: u8,
    passphrase: &[u8],
    salt: &[u8],
    count: u64,
    length: usize,
) -> Result<Vec<u8>, Error> {
    match hash {
        2 => Ok(s2k_iterated::<Sha1, 20>(passphrase, salt, count, length)),
        8 => Ok(s2k_iterated::<Sha256, 32>(passphrase, salt, count, length)),
        10 => Ok(s2k_iterated::<Sha512, 64>(passphrase, salt, count, length)),
        other => Err(Error::Unsupported(format!("S2K hash algorithm {other}"))),
    }
}

/// Open a message sealed with `passphrase` (a v4 symmetric-key session
/// packet, RFC 4880 section 5.3, with an iterated and salted S2K).
pub fn decrypt_with_passphrase(message: &[u8], passphrase: &[u8]) -> Result<Secret, Error> {
    let all = packets(message)?;
    let skesk = all
        .iter()
        .find(|p| p.tag == 3)
        .ok_or_else(|| malformed("the message is not sealed with a passphrase"))?;
    let mut r = Reader::new(&skesk.body);
    if r.byte("the passphrase session packet version")? != 4 {
        return Err(Error::Unsupported(
            "a passphrase session packet that is not version 4".into(),
        ));
    }
    let cipher = r.byte("its cipher")?;
    if r.byte("its S2K type")? != 3 {
        return Err(Error::Unsupported(
            "an S2K that is not iterated and salted".into(),
        ));
    }
    let hash = r.byte("its S2K hash")?;
    let salt = r.take(8, "its S2K salt")?;
    let count = s2k_count(r.byte("its S2K count")?);
    let mut derived = s2k(hash, passphrase, salt, count, key_len(cipher)?)?;
    let encrypted = r.rest();
    let result = if encrypted.is_empty() {
        open_data(&all, Some(cipher), &derived)
    } else {
        let aes = Aes::new(&derived).map_err(|e| malformed(e.to_string()))?;
        let mut m = encrypted.to_vec();
        cfb_decrypt(&aes, &[0u8; 16], &mut m);
        let session_cipher = m[0];
        let key = m[1..].to_vec();
        wipe(&mut m);
        open_data(&all, Some(session_cipher), &key)
    };
    wipe(&mut derived);
    result.map(Secret::new).map_err(|error| match error {
        Error::Integrity(_) => Error::BadPassphrase,
        other => other,
    })
}

/// `plaintext` sealed with `passphrase` as an OpenPGP message any
/// implementation opens: a v4 symmetric-key session packet with an iterated
/// and salted SHA-256 S2K at the format's highest count, and AES-256 in CFB
/// with a modification detection code over a literal data packet.
pub fn seal_with_passphrase(passphrase: &[u8], plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
    let salt = crate::random::bytes(8)?;
    let count_byte = 0xffu8;
    let mut key =
        s2k(8, passphrase, &salt, s2k_count(count_byte), 32).expect("SHA-256 is supported");
    let mut skesk = vec![4, 9, 3, 8];
    skesk.extend_from_slice(&salt);
    skesk.push(count_byte);
    let mut literal_body = vec![b'b', 0, 0, 0, 0, 0];
    literal_body.extend_from_slice(plaintext);
    let mut prefix = crate::random::bytes(16)?;
    prefix.extend_from_slice(&[prefix[14], prefix[15]]);
    let mut clear = prefix;
    clear.extend(write_packet(11, &literal_body));
    clear.extend_from_slice(&[0xd3, 0x14]);
    let mdc = sha1(&clear);
    clear.extend_from_slice(&mdc);
    let aes = Aes::new(&key).expect("a 32-byte key");
    cfb_encrypt(&aes, &[0u8; 16], &mut clear);
    wipe(&mut key);
    wipe(&mut literal_body);
    let mut seipd = vec![1];
    seipd.extend_from_slice(&clear);
    let mut out = write_packet(3, &skesk);
    out.extend(write_packet(18, &seipd));
    Ok(out)
}
