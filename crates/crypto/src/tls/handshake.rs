//! The TLS 1.3 client handshake (RFC 8446 section 4) over any byte stream:
//! one ClientHello offering X25519 and the three suites, the server's
//! flight checked — its certificate chain against the trust anchors and the
//! host, its CertificateVerify under the leaf's key, its Finished — and the
//! client's Finished; then application data both ways.
//!
//! Not offered, so never accepted: pre-shared keys and resumption, early
//! data, client certificates, HelloRetryRequest to another group, and any
//! version but TLS 1.3. A server answering any of those is refused naming
//! what it chose.

use std::io::{Read, Write};

use super::record::{
    self, Protection, RecordError, ALERT, APPLICATION_DATA, CHANGE_CIPHER_SPEC, HANDSHAKE,
};
use super::schedule::{traffic_key, Hash, Schedule};
use super::suite::{self, Aead, Suite};
use crate::ecdsa::{p256, p384};
use crate::rsa::{HashAlg, PublicKey as RsaKey};
use crate::x509::{ecdsa_der, verify_server_chain, Anchor, SubjectKey};

// Handshake message types (RFC 8446 section 4).
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const NEW_SESSION_TICKET: u8 = 4;
const ENCRYPTED_EXTENSIONS: u8 = 8;
const CERTIFICATE: u8 = 11;
const CERTIFICATE_REQUEST: u8 = 13;
const CERTIFICATE_VERIFY: u8 = 15;
const FINISHED: u8 = 20;
const KEY_UPDATE: u8 = 24;

// Extensions (RFC 8446 section 4.2, RFC 6066, RFC 7301).
const SERVER_NAME: u16 = 0;
const SUPPORTED_GROUPS: u16 = 10;
const SIGNATURE_ALGORITHMS: u16 = 13;
const ALPN: u16 = 16;
const SUPPORTED_VERSIONS: u16 = 43;
const KEY_SHARE: u16 = 51;

const X25519: u16 = 0x001d;
const TLS13: u16 = 0x0304;

// SignatureScheme values (RFC 8446 section 4.2.3) this client verifies.
const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
const ED25519: u16 = 0x0807;
const RSA_PKCS1_SHA256: u16 = 0x0401;
const RSA_PKCS1_SHA384: u16 = 0x0501;
const RSA_PKCS1_SHA512: u16 = 0x0601;
/// Offered for CertificateVerify and for the chain (signature_algorithms
/// covers both when signature_algorithms_cert is absent, RFC 8446 section
/// 4.2.3); PKCS#1 v1.5 only ever signs certificates.
const SCHEMES: [u16; 9] = [
    ECDSA_SECP256R1_SHA256,
    ECDSA_SECP384R1_SHA384,
    ED25519,
    RSA_PSS_RSAE_SHA256,
    RSA_PSS_RSAE_SHA384,
    RSA_PSS_RSAE_SHA512,
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,
];

/// The SHA-256 of "HelloRetryRequest", the random a HelloRetryRequest
/// carries in place of a ServerHello's (RFC 8446 section 4.1.3).
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// The most one handshake message may hold: the 2^24 - 1 its length field
/// states would let a server make the client hold 16 MiB; certificate
/// chains in the Web PKI stay far below the 64 KiB bound browsers (and
/// rustls's default max_handshake_message_len, 0xffff) keep.
const MAX_HANDSHAKE_MESSAGE: usize = 0xffff;

/// Why a TLS connection failed, said for the person reading.
#[derive(Debug)]
pub enum TlsError {
    Io(std::io::Error),
    Record(RecordError),
    /// The server sent a fatal alert: its description code and name.
    Alert(u8, &'static str),
    /// The server's messages were not what TLS 1.3 allows here.
    Protocol(String),
    /// The server's certificate or its signature did not hold.
    Certificate(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Io(error) => {
                write!(f, "the TLS connection failed reading or writing: {error}")
            }
            TlsError::Record(error) => error.fmt(f),
            TlsError::Alert(70, _) => f.write_str(
                "the server ended the TLS connection with alert 70 (protocol_version): it speaks \
                 TLS 1.2 or older; this client speaks TLS 1.3 only, so the server must enable TLS 1.3",
            ),
            TlsError::Alert(code, name) => write!(
                f,
                "the server ended the TLS connection with alert {code} ({name}): it refused \
                 something this client offered or sent"
            ),
            TlsError::Protocol(message) => write!(f, "the server broke TLS 1.3: {message}"),
            TlsError::Certificate(message) => {
                write!(f, "the server's certificate is not trusted: {message}")
            }
        }
    }
}

impl std::error::Error for TlsError {}

impl From<std::io::Error> for TlsError {
    fn from(error: std::io::Error) -> Self {
        TlsError::Io(error)
    }
}

impl From<RecordError> for TlsError {
    fn from(error: RecordError) -> Self {
        TlsError::Record(error)
    }
}

fn protocol<T>(message: impl Into<String>) -> Result<T, TlsError> {
    Err(TlsError::Protocol(message.into()))
}

/// The name RFC 8446 section 6 gives an alert description.
fn alert_name(code: u8) -> &'static str {
    match code {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "an alert RFC 8446 does not name",
    }
}

/// Reads from a byte slice, refusing a read past its end.
struct Reader<'a> {
    data: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], what: &'static str) -> Self {
        Self { data, what }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        if self.data.len() < n {
            return protocol(format!("the {} is cut short", self.what));
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, TlsError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TlsError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Result<usize, TlsError> {
        let bytes = self.take(3)?;
        Ok(usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2]))
    }

    fn vec8(&mut self) -> Result<&'a [u8], TlsError> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }

    fn vec16(&mut self) -> Result<&'a [u8], TlsError> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }

    fn vec24(&mut self) -> Result<&'a [u8], TlsError> {
        let n = self.u24()?;
        self.take(n)
    }

    fn done(&self) -> Result<(), TlsError> {
        match self.data.is_empty() {
            true => Ok(()),
            false => protocol(format!("the {} carries bytes past its end", self.what)),
        }
    }
}

fn push16(out: &mut Vec<u8>, body: &[u8]) {
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

fn extension(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    push16(out, body);
}

fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

/// The ClientHello: `random`, the X25519 `share`, `host` as SNI unless it
/// is an IP address (RFC 6066 section 3), and `alpn` when given.
fn client_hello(
    random: &[u8; 32],
    session: &[u8; 32],
    share: &[u8; 32],
    host: &str,
    alpn: &[&str],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(random);
    // A legacy session id, so middleboxes see a resumption-shaped hello
    // (RFC 8446 appendix D.4).
    body.push(32);
    body.extend_from_slice(session);
    let mut suites = Vec::new();
    for suite in suite::OFFERED {
        suites.extend_from_slice(&suite.code.to_be_bytes());
    }
    push16(&mut body, &suites);
    body.extend_from_slice(&[1, 0]);

    let mut extensions = Vec::new();
    if host.parse::<std::net::IpAddr>().is_err() {
        let mut name = vec![0];
        push16(&mut name, host.as_bytes());
        let mut list = Vec::new();
        push16(&mut list, &name);
        extension(&mut extensions, SERVER_NAME, &list);
    }
    extension(&mut extensions, SUPPORTED_GROUPS, &[0, 2, 0x00, 0x1d]);
    let mut schemes = Vec::new();
    for scheme in SCHEMES {
        schemes.extend_from_slice(&scheme.to_be_bytes());
    }
    let mut list = Vec::new();
    push16(&mut list, &schemes);
    extension(&mut extensions, SIGNATURE_ALGORITHMS, &list);
    if !alpn.is_empty() {
        let mut names = Vec::new();
        for protocol in alpn {
            names.push(protocol.len() as u8);
            names.extend_from_slice(protocol.as_bytes());
        }
        let mut list = Vec::new();
        push16(&mut list, &names);
        extension(&mut extensions, ALPN, &list);
    }
    extension(&mut extensions, SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);
    let mut entry = X25519.to_be_bytes().to_vec();
    push16(&mut entry, share);
    let mut shares = Vec::new();
    push16(&mut shares, &entry);
    extension(&mut extensions, KEY_SHARE, &shares);
    push16(&mut body, &extensions);
    handshake_message(CLIENT_HELLO, &body)
}

/// What the ServerHello chose.
struct Hello {
    suite: Suite,
    share: [u8; 32],
}

fn server_hello(body: &[u8], session: &[u8; 32]) -> Result<Hello, TlsError> {
    let mut reader = Reader::new(body, "ServerHello");
    let version = reader.u16()?;
    let random = reader.take(32)?;
    if random == HELLO_RETRY_RANDOM {
        return protocol(
            "it asked to retry the hello (HelloRetryRequest), and the only group this client \
             offers is X25519, which it already sent a share for",
        );
    }
    // RFC 8446 section 4.1.3: a TLS 1.3 server that negotiated an older
    // version sets this marker; seeing it means a downgrade.
    if random[24..31] == *b"DOWNGRD" {
        return protocol(
            "it signalled a downgrade below TLS 1.3, which this client does not speak",
        );
    }
    if reader.vec8()? != session {
        return protocol("it did not echo the hello's legacy session id");
    }
    let code = reader.u16()?;
    let Some(suite) = suite::by_code(code) else {
        return protocol(format!(
            "it chose cipher suite {code:#06x}, which this client did not offer"
        ));
    };
    if reader.u8()? != 0 {
        return protocol("it chose a compression method, which TLS 1.3 forbids");
    }
    let mut extensions = Reader::new(reader.vec16()?, "ServerHello extensions");
    reader.done()?;
    let mut chosen_version = None;
    let mut share = None;
    while !extensions.data.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vec16()?;
        let mut data = Reader::new(data, "ServerHello extension");
        match kind {
            SUPPORTED_VERSIONS => {
                chosen_version = Some(data.u16()?);
                data.done()?;
            }
            KEY_SHARE => {
                let group = data.u16()?;
                if group != X25519 {
                    return protocol(format!(
                        "it chose key share group {group:#06x}; this client offered X25519 only"
                    ));
                }
                let key = data.vec16()?;
                data.done()?;
                share = Some(<[u8; 32]>::try_from(key).map_err(|_| {
                    TlsError::Protocol("its X25519 key share is not 32 bytes".into())
                })?);
            }
            other => {
                return protocol(format!(
                    "its ServerHello carries extension {other}, which a ServerHello may not \
                     carry in answer to this client's hello"
                ))
            }
        }
    }
    match chosen_version {
        Some(TLS13) => {}
        Some(other) => {
            return protocol(format!(
                "it chose version {other:#06x}; this client speaks TLS 1.3 only"
            ))
        }
        None if version == 0x0303 => {
            return protocol("it answered with TLS 1.2 or older; this client speaks TLS 1.3 only")
        }
        None => {
            return protocol(format!(
                "it answered with version {version:#06x}; this client speaks TLS 1.3 only"
            ))
        }
    }
    let Some(share) = share else {
        return protocol("its ServerHello carries no key share");
    };
    Ok(Hello { suite, share })
}

/// The content CertificateVerify signs (RFC 8446 section 4.4.3).
fn signed_content(transcript_hash: &[u8]) -> Vec<u8> {
    let mut content = vec![0x20; 64];
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    content.push(0);
    content.extend_from_slice(transcript_hash);
    content
}

/// Whether `signature` with `scheme` over `content` holds under the leaf's
/// key. RFC 8446 section 4.4.3: RSA signs with PSS here, never PKCS#1 v1.5,
/// and each ECDSA scheme names its curve.
fn certificate_verify(
    key: &SubjectKey,
    scheme: u16,
    content: &[u8],
    signature: &[u8],
) -> Result<bool, TlsError> {
    let pss = |hash: HashAlg| match key {
        SubjectKey::Rsa { modulus, exponent } => Ok(RsaKey::new(modulus, exponent).verify_pss(
            hash,
            content,
            signature,
            hash.output_len(),
        )),
        _ => Err(()),
    };
    let checked = match (scheme, key) {
        (ECDSA_SECP256R1_SHA256, SubjectKey::P256 { x, y }) => Ok(ecdsa_der(signature)
            .is_some_and(|(r, s)| p256().verify(x, y, &HashAlg::Sha256.digest(content), r, s))),
        (ECDSA_SECP384R1_SHA384, SubjectKey::P384 { x, y }) => Ok(ecdsa_der(signature)
            .is_some_and(|(r, s)| p384().verify(x, y, &HashAlg::Sha384.digest(content), r, s))),
        (ED25519, SubjectKey::Ed25519(public)) => Ok(<&[u8; 64]>::try_from(signature)
            .is_ok_and(|signature| crate::ed25519::verify(public, content, signature))),
        (RSA_PSS_RSAE_SHA256, _) => pss(HashAlg::Sha256),
        (RSA_PSS_RSAE_SHA384, _) => pss(HashAlg::Sha384),
        (RSA_PSS_RSAE_SHA512, _) => pss(HashAlg::Sha512),
        _ => Err(()),
    };
    checked.or_else(|()| {
        protocol(format!(
            "its CertificateVerify uses scheme {scheme:#06x}, which does not fit its certificate's \
             key or was not offered"
        ))
    })
}

/// Reads records off the stream and hands out whole handshake messages.
struct Incoming<S> {
    stream: S,
    protection: Option<Protection>,
    pending: Vec<u8>,
    /// Set once the handshake is done, after which a change_cipher_spec
    /// record is no longer dropped but refused.
    established: bool,
    closed: bool,
}

impl<S: Read> Incoming<S> {
    /// One record: its type and content, opened when protection is on.
    fn record(&mut self) -> Result<(u8, Vec<u8>), TlsError> {
        loop {
            let mut head = [0u8; 5];
            self.stream
                .read_exact(&mut head)
                .map_err(|error| match error.kind() {
                    std::io::ErrorKind::UnexpectedEof => TlsError::Protocol(
                        "it closed the connection without a close_notify alert".into(),
                    ),
                    _ => TlsError::Io(error),
                })?;
            let length = usize::from(u16::from_be_bytes([head[3], head[4]]));
            if length > record::MAX_CIPHERTEXT {
                return Err(RecordError::Overflow(length).into());
            }
            let mut body = vec![0u8; length];
            self.stream.read_exact(&mut body)?;
            // RFC 8446 section 5: a change_cipher_spec record of one byte 1
            // may arrive during the handshake, for middlebox compatibility,
            // and is dropped.
            if head[0] == CHANGE_CIPHER_SPEC && body == [1] && !self.established {
                continue;
            }
            let (kind, content) = match (&mut self.protection, head[0]) {
                (Some(protection), APPLICATION_DATA) => protection.open(&head, &body)?,
                (Some(_), other) if other != ALERT => {
                    return protocol(format!(
                        "it sent an unprotected record of type {other} after the keys changed"
                    ))
                }
                _ => (head[0], body),
            };
            if kind == ALERT {
                let code = content.get(1).copied().unwrap_or(255);
                if code == 0 {
                    self.closed = true;
                }
                return Err(TlsError::Alert(code, alert_name(code)));
            }
            return Ok((kind, content));
        }
    }

    /// The next handshake message, whole: its type, body and bytes.
    fn message(&mut self) -> Result<(u8, Vec<u8>, Vec<u8>), TlsError> {
        loop {
            if self.pending.len() >= 4 {
                let length = usize::from(self.pending[1]) << 16
                    | usize::from(self.pending[2]) << 8
                    | usize::from(self.pending[3]);
                if length > MAX_HANDSHAKE_MESSAGE {
                    return protocol(format!(
                        "it sent a handshake message of {length} bytes, past the \
                         {MAX_HANDSHAKE_MESSAGE} this client takes"
                    ));
                }
                if self.pending.len() >= 4 + length {
                    let whole: Vec<u8> = self.pending.drain(..4 + length).collect();
                    return Ok((whole[0], whole[4..].to_vec(), whole));
                }
            }
            let (kind, content) = self.record()?;
            if kind != HANDSHAKE {
                return protocol(format!(
                    "it sent a record of type {kind} where a handshake message belongs"
                ));
            }
            if content.is_empty() {
                return protocol("it sent an empty handshake record");
            }
            self.pending.extend_from_slice(&content);
        }
    }

    /// Take protection on for the records that follow; refused when part
    /// of a handshake message is still pending, as RFC 8446 section 5.1
    /// requires messages not to span a key change.
    fn protect(&mut self, protection: Protection) -> Result<(), TlsError> {
        if !self.pending.is_empty() {
            return protocol("a handshake message spans the change of keys");
        }
        self.protection = Some(protection);
        Ok(())
    }
}

/// A TLS 1.3 connection after its handshake.
pub struct Connection<S> {
    incoming: Incoming<S>,
    outgoing: Protection,
    /// The protocol the server chose by ALPN, when one was offered.
    pub alpn: Option<String>,
    /// The suite negotiated, by its name.
    pub suite: &'static str,
}

/// Run the handshake over `stream` with `host`, trusting `anchors`, at
/// `now` (seconds since 1970); `alpn` offers application protocols.
pub fn connect<S: Read + Write>(
    mut stream: S,
    host: &str,
    anchors: &[Anchor],
    now: i64,
    alpn: &[&str],
) -> Result<Connection<S>, TlsError> {
    let random: [u8; 32] = crate::random::key()?;
    let session: [u8; 32] = crate::random::key()?;
    let mut secret = crate::random::key()?;
    let share = crate::x25519::public_key(&secret);
    let hello = client_hello(&random, &session, &share, host, alpn);
    let mut first = record::header(HANDSHAKE, hello.len()).to_vec();
    first.extend_from_slice(&hello);
    stream.write_all(&first)?;
    stream.flush()?;

    let mut incoming = Incoming {
        stream,
        protection: None,
        pending: Vec::new(),
        established: false,
        closed: false,
    };
    let (kind, body, whole) = incoming.message()?;
    if kind != SERVER_HELLO {
        return protocol(format!(
            "it answered the hello with handshake message {kind}, not a ServerHello"
        ));
    }
    let chosen = server_hello(&body, &session)?;
    let shared = crate::x25519::shared_secret(&secret, &chosen.share);
    crate::wipe::wipe(&mut secret);
    let Some(mut shared) = shared else {
        return protocol("its X25519 share gives an all-zero secret (a low-order point)");
    };
    let suite = chosen.suite;
    let hash: Hash = suite.hash;
    let mut transcript = hello;
    transcript.extend_from_slice(&whole);
    let schedule = Schedule::new(hash, &shared);
    crate::wipe::wipe(&mut shared);
    let (client_hs, server_hs) = schedule.handshake_traffic(&hash.digest(&transcript));
    let aead = |key: &[u8]| Aead::new(suite, key);
    incoming.protect(Protection::new(
        aead,
        &traffic_key(hash, &server_hs, suite.key_len),
    ))?;

    // EncryptedExtensions.
    let (kind, body, whole) = incoming.message()?;
    if kind != ENCRYPTED_EXTENSIONS {
        return protocol(format!(
            "it sent handshake message {kind} where EncryptedExtensions belongs"
        ));
    }
    let mut chosen_alpn = None;
    {
        let mut reader = Reader::new(&body, "EncryptedExtensions");
        let mut extensions = Reader::new(reader.vec16()?, "EncryptedExtensions");
        reader.done()?;
        while !extensions.data.is_empty() {
            let kind = extensions.u16()?;
            let data = extensions.vec16()?;
            if kind == ALPN {
                let mut list = Reader::new(data, "ALPN answer");
                let mut names = Reader::new(list.vec16()?, "ALPN answer");
                list.done()?;
                let name = String::from_utf8_lossy(names.vec8()?).into_owned();
                names.done()?;
                if !alpn.contains(&name.as_str()) {
                    return protocol(format!(
                        "it chose application protocol {name}, which this client did not offer"
                    ));
                }
                chosen_alpn = Some(name);
            }
        }
    }
    transcript.extend_from_slice(&whole);

    // Certificate (a CertificateRequest is refused: no client certificate).
    let (kind, body, whole) = incoming.message()?;
    if kind == CERTIFICATE_REQUEST {
        return protocol("it asks for a client certificate, which this client does not have");
    }
    if kind != CERTIFICATE {
        return protocol(format!(
            "it sent handshake message {kind} where its Certificate belongs"
        ));
    }
    let mut chain = Vec::new();
    {
        let mut reader = Reader::new(&body, "Certificate");
        if !reader.vec8()?.is_empty() {
            return protocol(
                "its Certificate carries a request context, which only answers a request",
            );
        }
        let mut entries = Reader::new(reader.vec24()?, "certificate list");
        reader.done()?;
        while !entries.data.is_empty() {
            chain.push(entries.vec24()?.to_vec());
            entries.vec16()?;
        }
    }
    let leaf_key = verify_server_chain(&chain, anchors, host, now)
        .map_err(|error| TlsError::Certificate(error.to_string()))?;
    transcript.extend_from_slice(&whole);

    // CertificateVerify, over the transcript through Certificate.
    let (kind, body, whole) = incoming.message()?;
    if kind != CERTIFICATE_VERIFY {
        return protocol(format!(
            "it sent handshake message {kind} where CertificateVerify belongs"
        ));
    }
    {
        let mut reader = Reader::new(&body, "CertificateVerify");
        let scheme = reader.u16()?;
        let signature = reader.vec16()?;
        reader.done()?;
        let content = signed_content(&hash.digest(&transcript));
        if !certificate_verify(&leaf_key, scheme, &content, signature)? {
            return Err(TlsError::Certificate(
                "its CertificateVerify signature does not hold under its certificate's key: the \
                 server does not hold the key its certificate names"
                    .into(),
            ));
        }
    }
    transcript.extend_from_slice(&whole);

    // The server's Finished, over the transcript through CertificateVerify.
    let (kind, body, whole) = incoming.message()?;
    if kind != FINISHED {
        return protocol(format!(
            "it sent handshake message {kind} where Finished belongs"
        ));
    }
    let expected = schedule.finished(&server_hs, &hash.digest(&transcript));
    if !crate::wipe::equal(&expected, &body) {
        return protocol(
            "its Finished does not match the handshake: the messages were altered on the way",
        );
    }
    transcript.extend_from_slice(&whole);
    let (client_ap, server_ap) = schedule.application_traffic(&hash.digest(&transcript));

    // The client's Finished, under the client handshake key.
    let mut outgoing = Protection::new(aead, &traffic_key(hash, &client_hs, suite.key_len));
    let verify_data = schedule.finished(&client_hs, &hash.digest(&transcript));
    let finished = outgoing.seal(HANDSHAKE, &handshake_message(FINISHED, &verify_data))?;
    incoming.stream.write_all(&finished)?;
    incoming.stream.flush()?;

    incoming.protect(Protection::new(
        aead,
        &traffic_key(hash, &server_ap, suite.key_len),
    ))?;
    incoming.established = true;
    Ok(Connection {
        incoming,
        outgoing: Protection::new(aead, &traffic_key(hash, &client_ap, suite.key_len)),
        alpn: chosen_alpn,
        suite: suite.name,
    })
}

impl<S: Read + Write> Connection<S> {
    /// Send `data` as application data, in records of at most 2^14 bytes.
    pub fn send(&mut self, data: &[u8]) -> Result<(), TlsError> {
        for chunk in data.chunks(record::MAX_PLAINTEXT) {
            let sealed = self.outgoing.seal(APPLICATION_DATA, chunk)?;
            self.incoming.stream.write_all(&sealed)?;
        }
        self.incoming.stream.flush()?;
        Ok(())
    }

    /// The next application data; empty once the server sent close_notify.
    /// NewSessionTicket messages are read and dropped (no resumption), and a
    /// KeyUpdate is refused.
    pub fn receive(&mut self) -> Result<Vec<u8>, TlsError> {
        if self.incoming.closed {
            return Ok(Vec::new());
        }
        loop {
            match self.incoming.record() {
                Ok((APPLICATION_DATA, content)) => {
                    if content.is_empty() {
                        continue;
                    }
                    return Ok(content);
                }
                Ok((HANDSHAKE, content)) => {
                    self.incoming.pending.extend_from_slice(&content);
                    while self.incoming.pending.len() >= 4 {
                        let length = usize::from(self.incoming.pending[1]) << 16
                            | usize::from(self.incoming.pending[2]) << 8
                            | usize::from(self.incoming.pending[3]);
                        if length > MAX_HANDSHAKE_MESSAGE {
                            return protocol(format!(
                                "it sent a handshake message of {length} bytes, past the \
                                 {MAX_HANDSHAKE_MESSAGE} this client takes"
                            ));
                        }
                        if self.incoming.pending.len() < 4 + length {
                            break;
                        }
                        let kind = self.incoming.pending[0];
                        self.incoming.pending.drain(..4 + length);
                        match kind {
                            NEW_SESSION_TICKET => {}
                            KEY_UPDATE => {
                                return protocol("it asked to update the traffic keys, which this client does not do")
                            }
                            other => {
                                return protocol(format!("it sent handshake message {other} after the handshake"))
                            }
                        }
                    }
                }
                Ok((other, _)) => {
                    return protocol(format!(
                        "it sent a record of type {other} after the handshake"
                    ))
                }
                Err(TlsError::Alert(0, _)) => return Ok(Vec::new()),
                Err(error) => return Err(error),
            }
        }
    }

    /// Everything the server sends until it closes.
    pub fn receive_all(&mut self) -> Result<Vec<u8>, TlsError> {
        let mut all = Vec::new();
        loop {
            let chunk = self.receive()?;
            if chunk.is_empty() {
                return Ok(all);
            }
            all.extend_from_slice(&chunk);
        }
    }

    /// Send close_notify.
    pub fn close(&mut self) -> Result<(), TlsError> {
        let sealed = self.outgoing.seal(ALERT, &[1, 0])?;
        self.incoming.stream.write_all(&sealed)?;
        self.incoming.stream.flush()?;
        Ok(())
    }
}
