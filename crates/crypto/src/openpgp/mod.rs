//! The OpenPGP that Skarbiec vaults were written in (RFC 4880, RFC 6637,
//! RFC 9580 and LibrePGP's OCB encrypted data packet), and no more: v4 keys
//! with an Ed25519 primary key and a Curve25519 encryption subkey; messages
//! encrypted to that subkey with ECDH (SHA-256, AES key wrap) carrying AES in
//! OCB or in CFB with a modification detection code, ZLIB or ZIP compressed;
//! passphrase-sealed messages; cleartext signatures by the primary key; and
//! the key files gpg-agent and keyboxd keep. Anything else is refused naming
//! what it is.

pub mod agent;
pub mod armor;
pub mod keyboxd;
pub mod keys;
pub mod message;
pub mod signature;

/// Why OpenPGP data was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The armor is missing, damaged or fails its checksum.
    Armor(String),
    /// The packets are cut short or malformed.
    Malformed(String),
    /// A standard feature Skarbiec never wrote and does not read.
    Unsupported(String),
    /// No secret key held here opens the message; the key ids it is for.
    NoKey(Vec<String>),
    /// An integrity check failed: the data was changed, or the key is wrong.
    Integrity(String),
    /// A signature does not verify.
    BadSignature(String),
    /// A passphrase that does not open what it is for.
    BadPassphrase,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Armor(why) => write!(formatter, "the OpenPGP armor is damaged: {why}"),
            Self::Malformed(why) => write!(formatter, "the OpenPGP data is malformed: {why}"),
            Self::Unsupported(what) => write!(
                formatter,
                "the OpenPGP data uses {what}, which Skarbiec never wrote and does not read"
            ),
            Self::NoKey(ids) => write!(
                formatter,
                "no secret key held here opens this message; it is encrypted to key id(s) {}",
                ids.join(", ")
            ),
            Self::Integrity(why) => write!(
                formatter,
                "the OpenPGP data fails its integrity check: {why}"
            ),
            Self::BadSignature(why) => {
                write!(formatter, "the OpenPGP signature does not verify: {why}")
            }
            Self::BadPassphrase => write!(formatter, "the passphrase does not open it"),
        }
    }
}

impl std::error::Error for Error {}

pub(crate) fn malformed(why: impl Into<String>) -> Error {
    Error::Malformed(why.into())
}

/// One packet: its tag and body.
#[derive(Debug, Clone)]
pub struct Packet {
    pub tag: u8,
    pub body: Vec<u8>,
}

/// A cursor over bytes that refuses to read past their end.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.at
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let rest = &self.data[self.at..];
        self.at = self.data.len();
        rest
    }

    pub(crate) fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], Error> {
        if self.remaining() < n {
            return Err(malformed(format!("{what} is cut short")));
        }
        let out = &self.data[self.at..self.at + n];
        self.at += n;
        Ok(out)
    }

    pub(crate) fn byte(&mut self, what: &str) -> Result<u8, Error> {
        Ok(self.take(1, what)?[0])
    }

    pub(crate) fn u16(&mut self, what: &str) -> Result<u16, Error> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self, what: &str) -> Result<u32, Error> {
        let b = self.take(4, what)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A multiprecision integer (RFC 4880 section 3.2): its bytes.
    pub(crate) fn mpi(&mut self, what: &str) -> Result<&'a [u8], Error> {
        let bits = usize::from(self.u16(what)?);
        self.take(bits.div_ceil(8), what)
    }
}

/// The length of a new-format body chunk; `Some(n)` with `true` for a
/// partial body chunk that more chunks follow.
fn new_length(reader: &mut Reader<'_>) -> Result<(usize, bool), Error> {
    let first = reader.byte("a packet length")?;
    Ok(match first {
        0..=191 => (usize::from(first), false),
        192..=223 => {
            let second = reader.byte("a packet length")?;
            (
                ((usize::from(first) - 192) << 8) + usize::from(second) + 192,
                false,
            )
        }
        224..=254 => (1usize << (first & 0x1f), true),
        255 => (reader.u32("a packet length")? as usize, false),
    })
}

/// Every packet in `data`, in order.
pub fn packets(data: &[u8]) -> Result<Vec<Packet>, Error> {
    let mut reader = Reader::new(data);
    let mut out = Vec::new();
    while reader.remaining() > 0 {
        let header = reader.byte("a packet header")?;
        if header & 0x80 == 0 {
            return Err(malformed(format!(
                "byte {header:#04x} is not a packet header"
            )));
        }
        if header & 0x40 != 0 {
            let tag = header & 0x3f;
            let mut body = Vec::new();
            loop {
                let (length, partial) = new_length(&mut reader)?;
                body.extend_from_slice(reader.take(length, "a packet body")?);
                if !partial {
                    break;
                }
            }
            out.push(Packet { tag, body });
        } else {
            let tag = (header >> 2) & 0x0f;
            let body = match header & 3 {
                0 => {
                    let n = usize::from(reader.byte("a packet length")?);
                    reader.take(n, "a packet body")?
                }
                1 => {
                    let n = usize::from(reader.u16("a packet length")?);
                    reader.take(n, "a packet body")?
                }
                2 => {
                    let n = reader.u32("a packet length")? as usize;
                    reader.take(n, "a packet body")?
                }
                _ => reader.rest(),
            };
            out.push(Packet {
                tag,
                body: body.to_vec(),
            });
        }
    }
    Ok(out)
}

/// A new-format packet with a five-octet length.
pub fn write_packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.push(0xc0 | tag);
    out.push(0xff);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// `bytes` as a multiprecision integer, its bit count from the first set bit.
pub(crate) fn write_mpi(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let trimmed = &bytes[start..];
    let bits = match trimmed.first() {
        Some(&first) => trimmed.len() * 8 - first.leading_zeros() as usize,
        None => 0,
    };
    let mut out = (bits as u16).to_be_bytes().to_vec();
    out.extend_from_slice(trimmed);
    out
}

/// Upper-case hex, as OpenPGP key ids and fingerprints are written.
pub fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}
