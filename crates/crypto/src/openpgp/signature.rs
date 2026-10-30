//! OpenPGP v4 EdDSA (Ed25519) signatures: verifying one over given data,
//! and the cleartext signature framework (RFC 4880 section 7) Skarbiec's
//! audit epochs are signed in.

use super::armor::{armor, dearmor};
use super::keys::{fingerprint, PublicKey, ALGO_EDDSA};
use super::{malformed, packets, write_packet, Error, Reader};
use crate::sha::{Digest, Sha256, Sha512};

/// The hash a v4 signature names, of `data` followed by its header and
/// trailer (RFC 4880 section 5.2.4).
fn digest(hash_algo: u8, data: &[u8], header: &[u8]) -> Result<Vec<u8>, Error> {
    let mut trailer = vec![4, 0xff];
    trailer.extend_from_slice(&(header.len() as u32).to_be_bytes());
    match hash_algo {
        8 => {
            let mut h = Sha256::new();
            h.update(data);
            h.update(header);
            h.update(&trailer);
            let mut out = vec![0u8; 32];
            h.finish_into(&mut out);
            Ok(out)
        }
        10 => {
            let mut h = Sha512::new();
            h.update(data);
            h.update(header);
            h.update(&trailer);
            let mut out = vec![0u8; 64];
            h.finish_into(&mut out);
            Ok(out)
        }
        other => Err(Error::Unsupported(format!(
            "signature hash algorithm {other}"
        ))),
    }
}

/// The 32 bytes of an EdDSA MPI, left-padded with the zeros its bit count
/// dropped.
fn padded32(mpi: &[u8]) -> Result<[u8; 32], Error> {
    if mpi.len() > 32 {
        return Err(malformed(
            "an EdDSA signature value is longer than 32 bytes",
        ));
    }
    let mut out = [0u8; 32];
    out[32 - mpi.len()..].copy_from_slice(mpi);
    Ok(out)
}

/// Verify the v4 EdDSA signature packet `body` by `public` over `data`.
pub fn verify_v4(public: &[u8; 32], body: &[u8], data: &[u8]) -> Result<u8, Error> {
    let mut r = Reader::new(body);
    if r.byte("a signature version")? != 4 {
        return Err(Error::Unsupported(
            "a signature that is not version 4".into(),
        ));
    }
    let kind = r.byte("a signature type")?;
    let algo = r.byte("a signature algorithm")?;
    if algo != ALGO_EDDSA {
        return Err(Error::Unsupported(format!("signature algorithm {algo}")));
    }
    let hash_algo = r.byte("a hash algorithm")?;
    let hashed_len = usize::from(r.u16("hashed subpackets")?);
    r.take(hashed_len, "hashed subpackets")?;
    let header = &body[..6 + hashed_len];
    let unhashed_len = usize::from(r.u16("unhashed subpackets")?);
    r.take(unhashed_len, "unhashed subpackets")?;
    let left16 = r.take(2, "the digest's first bytes")?;
    let rr = padded32(r.mpi("the signature's R")?)?;
    let ss = padded32(r.mpi("the signature's S")?)?;
    let digest = digest(hash_algo, data, header)?;
    if digest[..2] != *left16 {
        return Err(Error::BadSignature(
            "the signed data is not the data the signature was made over".into(),
        ));
    }
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&rr);
    signature[32..].copy_from_slice(&ss);
    if crate::ed25519::verify(public, &digest, &signature) {
        Ok(kind)
    } else {
        Err(Error::BadSignature(
            "the Ed25519 signature does not match the key and data".into(),
        ))
    }
}

/// The text a cleartext signature covers (RFC 4880 section 7.1): each line
/// with trailing spaces and tabs removed, joined by CR LF, no final line
/// break.
fn canonical_text(text: &str) -> Vec<u8> {
    text.split('\n')
        .map(|line| line.trim_end_matches(['\r']).trim_end_matches([' ', '\t']))
        .collect::<Vec<_>>()
        .join("\r\n")
        .into_bytes()
}

/// The issuer fingerprint (subpacket 33) or key id (16) a signature names.
fn issuer(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(body);
    r.take(4, "a signature header")?;
    let hashed_len = usize::from(r.u16("hashed subpackets")?);
    let hashed = super::keys::subpackets(r.take(hashed_len, "hashed subpackets")?)?;
    let unhashed_len = usize::from(r.u16("unhashed subpackets")?);
    let unhashed = super::keys::subpackets(r.take(unhashed_len, "unhashed subpackets")?)?;
    for (kind, data) in hashed.iter().chain(&unhashed) {
        if *kind == 33 && data.len() == 21 {
            return Ok(data[1..].to_vec());
        }
    }
    for (kind, data) in hashed.iter().chain(&unhashed) {
        if *kind == 16 {
            return Ok(data.clone());
        }
    }
    Err(malformed("the signature names no issuer"))
}

/// The text of a cleartext-signed message, verified against the first of
/// `keys` it names as issuer; the text as signed, dash-escaping removed and
/// lines joined by LF.
pub fn verify_cleartext(signed: &str, keys: &[PublicKey]) -> Result<String, Error> {
    let begin = "-----BEGIN PGP SIGNED MESSAGE-----";
    let start = signed
        .find(begin)
        .ok_or_else(|| Error::Armor(format!("there is no {begin} line")))?;
    let after = &signed[start + begin.len()..];
    let body_start = after
        .find("\n\n")
        .ok_or_else(|| malformed("the signed message has no header end"))?
        + 2;
    let sig_at = after
        .find("\n-----BEGIN PGP SIGNATURE-----")
        .ok_or_else(|| Error::Armor("there is no -----BEGIN PGP SIGNATURE----- line".into()))?;
    let escaped = &after[body_start..sig_at];
    let text: Vec<&str> = escaped
        .split('\n')
        .map(|line| line.strip_prefix("- ").unwrap_or(line))
        .collect();
    let text = text.join("\n");
    let signature = dearmor(&after[sig_at..], "PGP SIGNATURE")?;
    let packet = packets(&signature)?
        .into_iter()
        .find(|p| p.tag == 2)
        .ok_or_else(|| malformed("the signature block holds no signature"))?;
    let named = issuer(&packet.body)?;
    let key = keys
        .iter()
        .find(|k| k.fingerprint.ends_with(&named))
        .ok_or_else(|| Error::NoKey(vec![super::hex_upper(&named)]))?;
    let kind = verify_v4(&key.ed25519, &packet.body, &canonical_text(&text))?;
    if kind != 0x01 {
        return Err(Error::BadSignature(format!(
            "the signature has type {kind:#04x}, not a text signature"
        )));
    }
    Ok(text)
}

/// `text` cleartext-signed with `seed`, the Ed25519 secret of the primary
/// key whose packet body is `primary_body`.
pub fn sign_cleartext(seed: &[u8; 32], primary_body: &[u8], text: &str, created: u32) -> String {
    let issuer = fingerprint(primary_body);
    let body = super::keys::sign_v4(seed, &issuer, 0x01, created, &[], &canonical_text(text));
    let escaped: Vec<String> = text
        .split('\n')
        .map(|line| {
            if line.starts_with('-') {
                format!("- {line}")
            } else {
                line.to_string()
            }
        })
        .collect();
    let mut out = String::from("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n");
    out.push_str(&escaped.join("\n"));
    out.push('\n');
    out.push_str(&armor(&write_packet(2, &body), "PGP SIGNATURE"));
    out
}
