//! The secret key files gpg-agent keeps under `private-keys-v1.d`: the
//! extended key format (`Key: (private-key …)`), unprotected or protected
//! with `openpgp-s2k3-ocb-aes` (iterated and salted SHA-1, AES-128 in OCB,
//! the public parameters as associated data; GnuPG's agent/protect.c).

use super::{malformed, Error};
use crate::aes::Aes;
use crate::ocb::Ocb;
use crate::wipe::{wipe, Secret};

/// One S-expression value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sexp {
    Atom(Vec<u8>),
    List(Vec<Sexp>),
}

impl Sexp {
    fn name(&self) -> Option<&[u8]> {
        match self {
            Sexp::List(items) => match items.first() {
                Some(Sexp::Atom(name)) => Some(name),
                _ => None,
            },
            Sexp::Atom(_) => None,
        }
    }

    fn items(&self) -> &[Sexp] {
        match self {
            Sexp::List(items) => items,
            Sexp::Atom(_) => &[],
        }
    }

    /// The first sublist named `name`.
    fn find(&self, name: &[u8]) -> Option<&Sexp> {
        self.items().iter().find(|item| item.name() == Some(name))
    }

    fn atom(&self, index: usize) -> Option<&[u8]> {
        match self.items().get(index) {
            Some(Sexp::Atom(bytes)) => Some(bytes),
            _ => None,
        }
    }

    /// The canonical encoding (`(4:name3:val)`), what gpg-agent hashes and
    /// authenticates.
    pub fn canonical(&self) -> Vec<u8> {
        match self {
            Sexp::Atom(bytes) => {
                let mut out = format!("{}:", bytes.len()).into_bytes();
                out.extend_from_slice(bytes);
                out
            }
            Sexp::List(items) => {
                let mut out = vec![b'('];
                for item in items {
                    out.extend(item.canonical());
                }
                out.push(b')');
                out
            }
        }
    }
}

/// Parse the advanced (text) S-expression syntax gpg-agent writes: lists,
/// bare tokens, `"quoted"` strings and `#hex#` blobs.
pub fn parse_sexp(text: &[u8]) -> Result<Sexp, Error> {
    fn value(text: &[u8], at: &mut usize) -> Result<Sexp, Error> {
        skip(text, at);
        match text.get(*at) {
            Some(b'(') => {
                *at += 1;
                let mut items = Vec::new();
                loop {
                    skip(text, at);
                    match text.get(*at) {
                        Some(b')') => {
                            *at += 1;
                            return Ok(Sexp::List(items));
                        }
                        None => return Err(malformed("a key S-expression list is not closed")),
                        _ => items.push(value(text, at)?),
                    }
                }
            }
            Some(b'#') => {
                *at += 1;
                let mut hex = Vec::new();
                while let Some(&c) = text.get(*at) {
                    *at += 1;
                    if c == b'#' {
                        return Ok(Sexp::Atom(decode_hex(&hex)?));
                    }
                    if !c.is_ascii_whitespace() {
                        hex.push(c);
                    }
                }
                Err(malformed("a key S-expression #hex# value is not closed"))
            }
            Some(b'"') => {
                *at += 1;
                let mut out = Vec::new();
                while let Some(&c) = text.get(*at) {
                    *at += 1;
                    match c {
                        b'"' => return Ok(Sexp::Atom(out)),
                        b'\\' => {
                            let escaped = *text
                                .get(*at)
                                .ok_or_else(|| malformed("a quoted string ends in an escape"))?;
                            *at += 1;
                            out.push(match escaped {
                                b'n' => b'\n',
                                b'r' => b'\r',
                                b't' => b'\t',
                                other => other,
                            });
                        }
                        other => out.push(other),
                    }
                }
                Err(malformed("a key S-expression string is not closed"))
            }
            Some(_) => {
                let start = *at;
                while let Some(&c) = text.get(*at) {
                    if c.is_ascii_whitespace() || c == b'(' || c == b')' {
                        break;
                    }
                    *at += 1;
                }
                Ok(Sexp::Atom(text[start..*at].to_vec()))
            }
            None => Err(malformed("a key S-expression ends early")),
        }
    }
    fn skip(text: &[u8], at: &mut usize) {
        while text.get(*at).is_some_and(u8::is_ascii_whitespace) {
            *at += 1;
        }
    }
    let mut at = 0;
    value(text, &mut at)
}

/// Parse the canonical S-expression form (`(3:abc…)`).
pub fn parse_canonical(data: &[u8]) -> Result<Sexp, Error> {
    fn value(data: &[u8], at: &mut usize) -> Result<Sexp, Error> {
        match data.get(*at) {
            Some(b'(') => {
                *at += 1;
                let mut items = Vec::new();
                while data.get(*at) != Some(&b')') {
                    if *at >= data.len() {
                        return Err(malformed("a canonical S-expression list is not closed"));
                    }
                    items.push(value(data, at)?);
                }
                *at += 1;
                Ok(Sexp::List(items))
            }
            Some(c) if c.is_ascii_digit() => {
                let start = *at;
                while data.get(*at).is_some_and(u8::is_ascii_digit) {
                    *at += 1;
                }
                let len: usize = std::str::from_utf8(&data[start..*at])
                    .expect("digits")
                    .parse()
                    .map_err(|_| malformed("a canonical length is too large"))?;
                if data.get(*at) != Some(&b':') {
                    return Err(malformed("a canonical length has no colon"));
                }
                *at += 1;
                let bytes = data
                    .get(*at..*at + len)
                    .ok_or_else(|| malformed("a canonical value is cut short"))?;
                *at += len;
                Ok(Sexp::Atom(bytes.to_vec()))
            }
            _ => Err(malformed("a canonical S-expression has an unexpected byte")),
        }
    }
    let mut at = 0;
    value(data, &mut at)
}

fn decode_hex(hex: &[u8]) -> Result<Vec<u8>, Error> {
    if !hex.len().is_multiple_of(2) {
        return Err(malformed("a #hex# value has an odd number of digits"));
    }
    hex.chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or_else(|| malformed("a #hex# value holds a non-hex digit"))
        })
        .collect()
}

/// A secret key gpg-agent kept: its curve, public point and secret.
pub struct AgentKey {
    pub curve: String,
    /// The public point as the file holds it (`0x40 || key`).
    pub q: Vec<u8>,
    /// The secret as the file holds it: the Ed25519 seed, or the Curve25519
    /// scalar in big-endian MPI order.
    pub d: Secret,
}

impl AgentKey {
    /// The public key without its 0x40 prefix.
    pub fn public(&self) -> Result<[u8; 32], Error> {
        match self.q.as_slice() {
            [0x40, rest @ ..] if rest.len() == 32 => Ok(rest.try_into().expect("32")),
            _ => Err(malformed(
                "the key file's public point is not 0x40 and 32 bytes",
            )),
        }
    }

    /// The X25519 secret scalar in its native little-endian order:
    /// libgcrypt keeps a Curve25519 `d` as a big-endian number.
    pub fn x25519_secret(&self) -> Result<[u8; 32], Error> {
        let d = self.d.expose();
        if self.curve != "Curve25519" || d.len() > 32 {
            return Err(Error::Unsupported(format!(
                "a {} key where a Curve25519 key was expected",
                self.curve
            )));
        }
        let mut out = [0u8; 32];
        for (i, byte) in d.iter().rev().enumerate() {
            out[i] = *byte;
        }
        Ok(out)
    }

    /// The Ed25519 seed.
    pub fn ed25519_seed(&self) -> Result<[u8; 32], Error> {
        let d = self.d.expose();
        if self.curve != "Ed25519" || d.len() > 32 {
            return Err(Error::Unsupported(format!(
                "a {} key where an Ed25519 key was expected",
                self.curve
            )));
        }
        let mut out = [0u8; 32];
        out[32 - d.len()..].copy_from_slice(d);
        Ok(out)
    }
}

/// Whether the key file text holds a protected key.
pub fn is_protected(file: &str) -> bool {
    file.contains("(protected-private-key")
}

/// The curve and public point of a gpg-agent key file, read without its
/// secret: a protected key's public half is in the clear, so which file
/// holds which key is answered without a passphrase.
pub fn key_file_public(file: &str) -> Result<(String, Vec<u8>), Error> {
    let start = file
        .find("Key:")
        .ok_or_else(|| malformed("the key file has no Key: field"))?;
    let sexp = parse_sexp(file[start + 4..].as_bytes())?;
    let ecc = sexp
        .find(b"ecc")
        .ok_or_else(|| Error::Unsupported("a key that is not elliptic-curve".into()))?;
    let curve = ecc
        .find(b"curve")
        .and_then(|c| c.atom(1))
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .ok_or_else(|| malformed("the key names no curve"))?;
    let q = ecc
        .find(b"q")
        .and_then(|q| q.atom(1))
        .ok_or_else(|| malformed("the key has no public point q"))?
        .to_vec();
    Ok((curve, q))
}

/// The secret key in a gpg-agent key file. A protected key needs
/// `passphrase`; without one, or with the wrong one, it is refused saying
/// so.
pub fn read_key_file(file: &str, passphrase: Option<&[u8]>) -> Result<AgentKey, Error> {
    let start = file
        .find("Key:")
        .ok_or_else(|| malformed("the key file has no Key: field"))?;
    let rest = &file[start + 4..];
    // The value runs to the end of its balanced list.
    let sexp = parse_sexp(rest.as_bytes())?;
    let kind = sexp
        .atom(0)
        .ok_or_else(|| malformed("the key file's Key: is not a named list"))?;
    let ecc = sexp
        .find(b"ecc")
        .ok_or_else(|| Error::Unsupported("a key that is not elliptic-curve".into()))?;
    let curve = ecc
        .find(b"curve")
        .and_then(|c| c.atom(1))
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .ok_or_else(|| malformed("the key names no curve"))?;
    let q = ecc
        .find(b"q")
        .and_then(|q| q.atom(1))
        .ok_or_else(|| malformed("the key has no public point q"))?
        .to_vec();
    let d = match kind {
        b"private-key" => ecc
            .find(b"d")
            .and_then(|d| d.atom(1))
            .ok_or_else(|| malformed("the key has no secret d"))?
            .to_vec(),
        b"protected-private-key" => {
            let passphrase = passphrase.ok_or(Error::BadPassphrase)?;
            unprotect(ecc, passphrase)?
        }
        other => {
            return Err(Error::Unsupported(format!(
                "a key file of kind {}",
                String::from_utf8_lossy(other)
            )))
        }
    };
    Ok(AgentKey {
        curve,
        q,
        d: Secret::new(d),
    })
}

/// Open the `(protected openpgp-s2k3-ocb-aes ((sha1 salt count) nonce)
/// data)` list of `ecc` with `passphrase`.
fn unprotect(ecc: &Sexp, passphrase: &[u8]) -> Result<Vec<u8>, Error> {
    let items = ecc.items();
    let hole = items
        .iter()
        .position(|item| item.name() == Some(b"protected"))
        .ok_or_else(|| malformed("a protected key has no protected list"))?;
    let protected = &items[hole];
    let mode = protected
        .atom(1)
        .ok_or_else(|| malformed("the protected list names no mode"))?;
    if mode != b"openpgp-s2k3-ocb-aes" {
        return Err(Error::Unsupported(format!(
            "key protection {}",
            String::from_utf8_lossy(mode)
        )));
    }
    let params = protected
        .items()
        .get(2)
        .ok_or_else(|| malformed("the protected list has no parameters"))?;
    let s2k = params
        .items()
        .first()
        .ok_or_else(|| malformed("the protection has no S2K"))?;
    if s2k.atom(0) != Some(b"sha1") {
        return Err(Error::Unsupported(
            "key protection S2K that is not SHA-1".into(),
        ));
    }
    let salt = s2k
        .atom(1)
        .filter(|s| s.len() == 8)
        .ok_or_else(|| malformed("the S2K salt is not 8 bytes"))?;
    let count_text = s2k
        .atom(2)
        .ok_or_else(|| malformed("the S2K has no count"))?;
    let mut count: u64 = std::str::from_utf8(count_text)
        .ok()
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| malformed("the S2K count is not a number"))?;
    if count < 256 {
        count = (16 + (count & 15)) << ((count >> 4) + 6);
    }
    let nonce = params
        .atom(1)
        .filter(|n| n.len() == 12)
        .ok_or_else(|| malformed("the OCB nonce is not 12 bytes"))?;
    let data = protected
        .atom(3)
        .ok_or_else(|| malformed("the protected list holds no data"))?;
    // The associated data is the key's list without the protected list.
    let ecc_canonical = ecc.canonical();
    let mut before = vec![b'('];
    for item in &items[..hole] {
        before.extend(item.canonical());
    }
    let after_start = before.len() + protected.canonical().len();
    let mut aad = before;
    aad.extend_from_slice(&ecc_canonical[after_start..]);
    let mut key = s2k_iterated_sha1(passphrase, salt, count, 16);
    let aes = Aes::new(&key).map_err(|e| malformed(e.to_string()))?;
    wipe(&mut key);
    let ocb = Ocb::new(&aes, 16).map_err(|e| malformed(e.to_string()))?;
    let mut clear = ocb
        .open(nonce, &aad, data)
        .map_err(|_| Error::BadPassphrase)?;
    let parsed = parse_canonical(&clear);
    wipe(&mut clear);
    let parsed = parsed?;
    let inner = parsed
        .items()
        .first()
        .ok_or_else(|| malformed("the unprotected key holds no list"))?;
    let d = inner
        .items()
        .iter()
        .find(|item| item.name() == Some(b"d"))
        .or_else(|| (inner.name() == Some(b"d")).then_some(inner))
        .and_then(|d| d.atom(1))
        .ok_or_else(|| malformed("the unprotected key holds no d"))?;
    Ok(d.to_vec())
}

/// Iterated and salted S2K (RFC 4880 section 3.7.1.3) over SHA-1: `count`
/// bytes of salt || passphrase repeated, hashed; longer keys by preloading
/// zero bytes.
pub fn s2k_iterated_sha1(passphrase: &[u8], salt: &[u8], count: u64, length: usize) -> Vec<u8> {
    s2k_iterated::<crate::sha::Sha1, 20>(passphrase, salt, count, length)
}

/// Iterated and salted S2K (RFC 4880 section 3.7.1.3) over any hash here,
/// `N` its digest length.
pub fn s2k_iterated<D: crate::sha::Digest, const N: usize>(
    passphrase: &[u8],
    salt: &[u8],
    count: u64,
    length: usize,
) -> Vec<u8> {
    let mut input = salt.to_vec();
    input.extend_from_slice(passphrase);
    let count = count.max(input.len() as u64);
    let mut out = Vec::with_capacity(length);
    let mut preload = 0;
    while out.len() < length {
        let mut hash = D::new();
        hash.update(&vec![0u8; preload]);
        let mut left = count;
        while left > 0 {
            let take = left.min(input.len() as u64) as usize;
            hash.update(&input[..take]);
            left -= take as u64;
        }
        let mut digest = [0u8; N];
        hash.finish_into(&mut digest);
        let take = (length - out.len()).min(N);
        out.extend_from_slice(&digest[..take]);
        wipe(&mut digest);
        preload += 1;
    }
    wipe(&mut input);
    out
}
