//! X.509 certificates (RFC 5280) as a TLS 1.3 client needs them: read the
//! DER (X.690), check that the chain a server sends leads, signature by
//! signature, from a trust anchor to a certificate that names the host, and
//! answer the key the handshake's CertificateVerify is then checked with.
//!
//! What is checked, each refused with what failed and why: every
//! certificate's validity window, its signature by its issuer's key under
//! the algorithm it states (RSA PKCS#1 v1.5 with SHA-256/384/512, ECDSA
//! P-256/P-384, Ed25519), that each issuer is a CA (basicConstraints cA, and
//! keyCertSign when keyUsage is present) within its path length, that no
//! certificate carries an extension twice or a critical one this reader
//! does not know, that the leaf names the host (subjectAltName, RFC 6125
//! with one leftmost wildcard label) and may serve TLS (extKeyUsage, when
//! present, names serverAuth). Name constraints and revocation are not
//! checked: a CA whose intermediate states name constraints is refused
//! because the extension is critical, never silently trusted wider.

use crate::ecdsa::{p256, p384};
use crate::rsa::{HashAlg, PublicKey as RsaKey};

/// Why a certificate or a chain was refused, said for the person reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertError(pub String);

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CertError {}

fn refuse<T>(message: impl Into<String>) -> Result<T, CertError> {
    Err(CertError(message.into()))
}

// X.690 universal tags and the context tags RFC 5280 uses.
const BOOLEAN: u8 = 0x01;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const NULL: u8 = 0x05;
const OID: u8 = 0x06;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const SEQUENCE: u8 = 0x30;
const VERSION: u8 = 0xa0;
const EXTENSIONS: u8 = 0xa3;
const DNS_NAME: u8 = 0x82;
const IP_ADDRESS: u8 = 0x87;

// Object identifiers, as their DER contents (RFC 8017 appendix C, RFC 5480,
// RFC 5758, RFC 8410, RFC 5280 section 4.2.1).
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const SHA512_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const ANY_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
/// Extensions a CA marks critical that change nothing this reader decides:
/// certificatePolicies (2.5.29.32) and policyConstraints (2.5.29.36), whose
/// policies a TLS client that requires no particular policy accepts
/// whatever they say (RFC 5280 section 6.1.1 with an any-policy initial set).
const IGNORABLE_CRITICAL: &[&[u8]] = &[&[0x55, 0x1d, 0x20], &[0x55, 0x1d, 0x24]];

/// The RSA modulus sizes accepted: at least the 2048 bits the CA/Browser
/// Forum Baseline Requirements (section 6.1.5) require of every publicly
/// trusted key, and at most the 8192 webpki's RSA_PKCS1_2048_8192
/// algorithms accept, which bounds the work one signature costs.
const RSA_MIN_BITS: usize = 2048;
const RSA_MAX_BITS: usize = 8192;
/// The largest public exponent accepted: 2^256 - 1, the top of the range
/// the Baseline Requirements (section 6.1.6) state for it.
const RSA_MAX_EXPONENT_BYTES: usize = 32;
/// The most certificates a chain is walked through. RFC 5280 states no
/// bound; this is Mozilla NSS's and Chromium's limit of eight
/// intermediates, plus the leaf.
const MAX_CHAIN: usize = 9;

/// A DER element as `element` reads it: its tag, its contents, the whole
/// element, and what follows it.
type Element<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// One DER element (X.690 section 8.1, definite lengths in their shortest
/// form as section 10.1 requires).
fn element(data: &[u8]) -> Result<Element<'_>, CertError> {
    let Some((&tag, rest)) = data.split_first() else {
        return refuse("a DER element ends before its tag");
    };
    if tag & 0x1f == 0x1f {
        return refuse(format!(
            "a DER element uses the high tag number form ({tag:#04x}), which no certificate field takes"
        ));
    }
    let Some((&first, rest)) = rest.split_first() else {
        return refuse("a DER element ends before its length");
    };
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 {
            return refuse("a DER element has an indefinite length, which DER forbids");
        }
        if count > std::mem::size_of::<usize>() || rest.len() < count {
            return refuse("a DER element states a length longer than the data");
        }
        if rest[0] == 0 {
            return refuse("a DER length has a leading zero byte, which DER forbids");
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |length, &byte| (length << 8) | usize::from(byte));
        if length < 0x80 {
            return refuse("a DER length under 128 is in the long form, which DER forbids");
        }
        (length, &rest[count..])
    };
    if rest.len() < length {
        return refuse(format!(
            "a DER element states {length} bytes and {} remain: the certificate is cut short",
            rest.len()
        ));
    }
    let header = data.len() - rest.len();
    Ok((
        tag,
        &rest[..length],
        &data[..header + length],
        &rest[length..],
    ))
}

/// The element with `tag` at the start of `data`, refused naming `what`.
fn expect<'a>(data: &'a [u8], tag: u8, what: &str) -> Result<(&'a [u8], &'a [u8]), CertError> {
    let (found, contents, _, rest) = element(data)?;
    if found != tag {
        return refuse(format!(
            "{what} should be DER tag {tag:#04x} and is {found:#04x}"
        ));
    }
    Ok((contents, rest))
}

/// A subject's public key, as a certificate states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectKey {
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    P256 { x: Vec<u8>, y: Vec<u8> },
    P384 { x: Vec<u8>, y: Vec<u8> },
    Ed25519([u8; 32]),
}

/// How a certificate is signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaPkcs1(HashAlg),
    Ecdsa(HashAlg),
    Ed25519,
}

fn algorithm(identifier: &[u8]) -> Result<Algorithm, CertError> {
    let (oid, parameters) = expect(identifier, OID, "the signature algorithm")?;
    let algorithm = match oid {
        SHA256_WITH_RSA => Algorithm::RsaPkcs1(HashAlg::Sha256),
        SHA384_WITH_RSA => Algorithm::RsaPkcs1(HashAlg::Sha384),
        SHA512_WITH_RSA => Algorithm::RsaPkcs1(HashAlg::Sha512),
        ECDSA_SHA256 => Algorithm::Ecdsa(HashAlg::Sha256),
        ECDSA_SHA384 => Algorithm::Ecdsa(HashAlg::Sha384),
        ECDSA_SHA512 => Algorithm::Ecdsa(HashAlg::Sha512),
        ED25519 => Algorithm::Ed25519,
        other => {
            return refuse(format!(
                "the certificate is signed with algorithm {}, which this client does not verify \
                 (it verifies RSA PKCS#1 v1.5 with SHA-256/384/512, ECDSA with SHA-256/384/512 \
                 and Ed25519)",
                dotted(other)
            ))
        }
    };
    // RFC 4055 section 5: RSA identifiers carry NULL parameters (some
    // encoders omit them); RFC 5758 section 3.2 and RFC 8410 section 3: the
    // ECDSA and Ed25519 ones carry none.
    let allowed = match algorithm {
        Algorithm::RsaPkcs1(_) => parameters.is_empty() || parameters == [NULL, 0],
        _ => parameters.is_empty(),
    };
    if !allowed {
        return refuse(format!(
            "the signature algorithm {} carries parameters its RFC forbids",
            dotted(oid)
        ));
    }
    Ok(algorithm)
}

/// An object identifier in dotted form, for a message.
fn dotted(oid: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut value: u64 = 0;
    for (index, &byte) in oid.iter().enumerate() {
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            if parts.is_empty() {
                let first = (value / 40).min(2);
                parts.push(first.to_string());
                parts.push((value - first * 40).to_string());
            } else {
                parts.push(value.to_string());
            }
            value = 0;
        } else if index + 1 == oid.len() {
            parts.push("(cut short)".to_string());
        }
    }
    parts.join(".")
}

/// The contents of a BIT STRING whose length is whole bytes.
fn whole_bits<'a>(contents: &'a [u8], what: &str) -> Result<&'a [u8], CertError> {
    match contents.split_first() {
        Some((0, bits)) => Ok(bits),
        _ => refuse(format!("{what} is a BIT STRING that is not whole bytes")),
    }
}

/// A SubjectPublicKeyInfo (RFC 5280 section 4.1.2.7).
fn subject_key(info: &[u8]) -> Result<SubjectKey, CertError> {
    let (identifier, rest) = expect(info, SEQUENCE, "the public key's algorithm")?;
    let (bits, _) = expect(rest, BIT_STRING, "the public key")?;
    let key = whole_bits(bits, "the public key")?;
    let (oid, parameters) = expect(identifier, OID, "the public key's algorithm")?;
    match oid {
        RSA_ENCRYPTION => {
            let (body, _) = expect(key, SEQUENCE, "the RSA public key")?;
            let (modulus, rest) = expect(body, INTEGER, "the RSA modulus")?;
            let (exponent, _) = expect(rest, INTEGER, "the RSA exponent")?;
            let modulus = unsigned(modulus, "the RSA modulus")?;
            let exponent = unsigned(exponent, "the RSA exponent")?;
            let bits =
                modulus.len() * 8 - modulus.first().map_or(8, |b| b.leading_zeros() as usize);
            if !(RSA_MIN_BITS..=RSA_MAX_BITS).contains(&bits) {
                return refuse(format!(
                    "an RSA key of {bits} bits; this client accepts {RSA_MIN_BITS} to {RSA_MAX_BITS}"
                ));
            }
            if exponent.len() > RSA_MAX_EXPONENT_BYTES || exponent.last().is_none_or(|b| b & 1 == 0)
            {
                return refuse("an RSA public exponent that is even, zero or past 2^256 - 1");
            }
            Ok(SubjectKey::Rsa {
                modulus: modulus.to_vec(),
                exponent: exponent.to_vec(),
            })
        }
        EC_PUBLIC_KEY => {
            let (curve, _) = expect(parameters, OID, "the EC key's named curve")?;
            let size = match curve {
                PRIME256V1 => 32,
                SECP384R1 => 48,
                other => {
                    return refuse(format!(
                        "an EC key on curve {}; this client takes P-256 and P-384",
                        dotted(other)
                    ))
                }
            };
            // SEC 1 section 2.3.3: an uncompressed point, 0x04 || x || y.
            if key.len() != 1 + 2 * size || key[0] != 4 {
                return refuse("an EC public key that is not an uncompressed point of its curve");
            }
            let (x, y) = (key[1..=size].to_vec(), key[1 + size..].to_vec());
            Ok(match size {
                32 => SubjectKey::P256 { x, y },
                _ => SubjectKey::P384 { x, y },
            })
        }
        ED25519 => match <[u8; 32]>::try_from(key) {
            Ok(key) if parameters.is_empty() => Ok(SubjectKey::Ed25519(key)),
            _ => refuse("an Ed25519 public key that is not 32 bytes, or carries parameters"),
        },
        other => refuse(format!(
            "a public key of algorithm {}, which this client does not take",
            dotted(other)
        )),
    }
}

/// A DER INTEGER as an unsigned big-endian number, refusing a negative one.
fn unsigned<'a>(contents: &'a [u8], what: &str) -> Result<&'a [u8], CertError> {
    match contents {
        [] => refuse(format!("{what} is an empty INTEGER")),
        [first, ..] if first & 0x80 != 0 => refuse(format!("{what} is negative")),
        [0, rest @ ..] => Ok(rest),
        all => Ok(all),
    }
}

/// Days from 1970-01-01 to a civil date (Howard Hinnant's days_from_civil,
/// the proleptic Gregorian calendar RFC 5280 times use).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// A UTCTime or GeneralizedTime as seconds since 1970, in the forms RFC
/// 5280 section 4.1.2.5 allows: seconds present, Z, no fraction.
fn time(tag: u8, contents: &[u8]) -> Result<i64, CertError> {
    let text = std::str::from_utf8(contents)
        .map_err(|_| CertError("a certificate time is not ASCII".into()))?;
    let digits = match tag {
        UTC_TIME => 12,
        GENERALIZED_TIME => 14,
        other => return refuse(format!("a certificate time has tag {other:#04x}")),
    };
    let Some(body) = text.strip_suffix('Z') else {
        return refuse(format!("the certificate time {text} is not in UTC (Z)"));
    };
    if body.len() != digits || !body.bytes().all(|b| b.is_ascii_digit()) {
        return refuse(format!(
            "the certificate time {text} is not of the form RFC 5280 requires"
        ));
    }
    let number = |range: std::ops::Range<usize>| -> i64 { body[range].parse().unwrap_or(0) };
    let (year, rest) = match tag {
        // RFC 5280 section 4.1.2.5.1: YY of 50 and above is 19YY.
        UTC_TIME => match number(0..2) {
            year if year >= 50 => (1900 + year, 2),
            year => (2000 + year, 2),
        },
        _ => (number(0..4), 4),
    };
    let field = |index: usize| number(rest + index * 2..rest + index * 2 + 2);
    let (month, day, hour, minute, second) = (field(0), field(1), field(2), field(3), field(4));
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return refuse(format!("the certificate time {text} is not a real moment"));
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// One certificate, read.
#[derive(Debug, Clone)]
pub struct Certificate {
    tbs: Vec<u8>,
    algorithm: Algorithm,
    signature: Vec<u8>,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    not_before: i64,
    not_after: i64,
    key: SubjectKey,
    /// None when not a CA; else how many CA certificates may sit below it
    /// (pathLenConstraint), `usize::MAX` when it states none.
    ca: Option<usize>,
    key_cert_sign: Option<bool>,
    dns_names: Vec<String>,
    ip_addresses: Vec<Vec<u8>>,
    server_auth: Option<bool>,
}

impl Certificate {
    /// Read one DER certificate; refused naming the field that is wrong.
    pub fn from_der(der: &[u8]) -> Result<Self, CertError> {
        let (certificate, trailing) = expect(der, SEQUENCE, "the certificate")?;
        if !trailing.is_empty() {
            return refuse("bytes follow the certificate's DER");
        }
        let (_, tbs_contents, tbs, rest) = element(certificate)?;
        let (outer_algorithm, rest) =
            expect(rest, SEQUENCE, "the certificate's signatureAlgorithm")?;
        let (signature, _) = expect(rest, BIT_STRING, "the certificate's signature")?;
        let signature = whole_bits(signature, "the certificate's signature")?.to_vec();

        let mut rest = tbs_contents;
        let mut version = 0;
        if rest.first() == Some(&VERSION) {
            let (explicit, after) = expect(rest, VERSION, "the version")?;
            let (number, _) = expect(explicit, INTEGER, "the version")?;
            version = match number {
                [value] if *value <= 2 => *value,
                _ => return refuse("the certificate states a version past v3"),
            };
            rest = after;
        }
        let (_, rest) = expect(rest, INTEGER, "the serial number")?;
        let (inner_algorithm, rest) =
            expect(rest, SEQUENCE, "the tbsCertificate's signature algorithm")?;
        if inner_algorithm != outer_algorithm {
            // RFC 5280 section 4.1.1.2.
            return refuse("the certificate states two different signature algorithms");
        }
        let algorithm = algorithm(inner_algorithm)?;
        let (_, _, issuer, rest) = element(rest)?;
        let (validity, rest) = expect(rest, SEQUENCE, "the validity")?;
        let (start_tag, start, _, after) = element(validity)?;
        let (end_tag, end, _, _) = element(after)?;
        let (not_before, not_after) = (time(start_tag, start)?, time(end_tag, end)?);
        let (_, _, subject, rest) = element(rest)?;
        let (info, mut rest) = expect(rest, SEQUENCE, "the subject public key info")?;
        let key = subject_key(info)?;

        let mut certificate = Certificate {
            tbs: tbs.to_vec(),
            algorithm,
            signature,
            issuer: issuer.to_vec(),
            subject: subject.to_vec(),
            not_before,
            not_after,
            key,
            ca: None,
            key_cert_sign: None,
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            server_auth: None,
        };
        // issuerUniqueID [1] and subjectUniqueID [2] are skipped.
        while let Some(&tag) = rest.first() {
            let (_, contents, _, after) = element(rest)?;
            if tag == EXTENSIONS {
                if version != 2 {
                    return refuse("a certificate before v3 carries extensions");
                }
                certificate.extensions(contents)?;
            }
            rest = after;
        }
        Ok(certificate)
    }

    fn extensions(&mut self, explicit: &[u8]) -> Result<(), CertError> {
        let (mut list, _) = expect(explicit, SEQUENCE, "the extensions")?;
        let mut seen: Vec<&[u8]> = Vec::new();
        while !list.is_empty() {
            let (extension, after) = expect(list, SEQUENCE, "an extension")?;
            list = after;
            let (oid, rest) = expect(extension, OID, "an extension's id")?;
            if seen.contains(&oid) {
                // RFC 5280 section 4.2.
                return refuse(format!(
                    "the certificate carries extension {} twice",
                    dotted(oid)
                ));
            }
            seen.push(oid);
            let (critical, rest) = match rest.first() {
                Some(&BOOLEAN) => {
                    let (value, after) = expect(rest, BOOLEAN, "an extension's critical flag")?;
                    (value == [0xff], after)
                }
                _ => (false, rest),
            };
            let (value, _) = expect(rest, OCTET_STRING, "an extension's value")?;
            match oid {
                BASIC_CONSTRAINTS => {
                    let (body, _) = expect(value, SEQUENCE, "basicConstraints")?;
                    let (is_ca, rest) = match body.first() {
                        Some(&BOOLEAN) => {
                            let (flag, after) = expect(body, BOOLEAN, "basicConstraints cA")?;
                            (flag == [0xff], after)
                        }
                        _ => (false, body),
                    };
                    let path = match rest.first() {
                        Some(&INTEGER) => {
                            let (length, _) = expect(rest, INTEGER, "pathLenConstraint")?;
                            let length = unsigned(length, "pathLenConstraint")?;
                            Some(length.iter().fold(0usize, |n, &b| {
                                n.saturating_mul(256).saturating_add(usize::from(b))
                            }))
                        }
                        _ => None,
                    };
                    self.ca = is_ca.then_some(path.unwrap_or(usize::MAX));
                }
                KEY_USAGE => {
                    let (bits, _) = expect(value, BIT_STRING, "keyUsage")?;
                    // RFC 5280 section 4.2.1.3: keyCertSign is bit 5, the
                    // sixth from the top of the first byte.
                    self.key_cert_sign = Some(bits.get(1).is_some_and(|byte| byte & 0x04 != 0));
                }
                SUBJECT_ALT_NAME => {
                    let (mut names, _) = expect(value, SEQUENCE, "subjectAltName")?;
                    while !names.is_empty() {
                        let (tag, contents, _, after) = element(names)?;
                        names = after;
                        match tag {
                            DNS_NAME => self.dns_names.push(
                                std::str::from_utf8(contents)
                                    .map_err(|_| CertError("a dNSName is not ASCII".into()))?
                                    .to_ascii_lowercase(),
                            ),
                            IP_ADDRESS => self.ip_addresses.push(contents.to_vec()),
                            _ => {}
                        }
                    }
                }
                EXT_KEY_USAGE => {
                    let (mut purposes, _) = expect(value, SEQUENCE, "extKeyUsage")?;
                    let mut server = false;
                    while !purposes.is_empty() {
                        let (purpose, after) = expect(purposes, OID, "an extKeyUsage purpose")?;
                        server |= purpose == SERVER_AUTH || purpose == ANY_EXTENDED_KEY_USAGE;
                        purposes = after;
                    }
                    self.server_auth = Some(server);
                }
                other if critical && !IGNORABLE_CRITICAL.contains(&other) => {
                    // RFC 5280 section 4.2.
                    return refuse(format!(
                        "the certificate marks extension {} critical, and this client does not \
                         know it, so it cannot honour what it restricts",
                        dotted(other)
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// The subject's public key.
    pub fn key(&self) -> &SubjectKey {
        &self.key
    }

    /// The subject's name for a message: its common name and organisation.
    pub fn subject_name(&self) -> String {
        describe(&self.subject)
    }

    /// When the certificate stops being valid, in seconds since 1970.
    pub fn not_after(&self) -> i64 {
        self.not_after
    }

    fn within(&self, now: i64, role: &str) -> Result<(), CertError> {
        if now < self.not_before {
            return refuse(format!(
                "the {role} certificate for {} is not valid yet (from {} seconds since 1970, now \
                 {now}): the host's clock is behind or the certificate was issued ahead",
                self.subject_name(),
                self.not_before
            ));
        }
        if now > self.not_after {
            return refuse(format!(
                "the {role} certificate for {} expired (at {} seconds since 1970, now {now}): \
                 the server must renew it, or the host's clock is ahead",
                self.subject_name(),
                self.not_after
            ));
        }
        Ok(())
    }

    fn signed_by(&self, key: &SubjectKey) -> bool {
        verify(key, self.algorithm, &self.tbs, &self.signature)
    }

    /// Whether the certificate names `host`: a DNS name (RFC 6125 section
    /// 6.4, a `*` only as the whole leftmost label, matching one label) or
    /// an IP address literal against its iPAddress entries.
    pub fn names_host(&self, host: &str) -> bool {
        if let Ok(address) = host.parse::<std::net::IpAddr>() {
            let octets = match address {
                std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            return self.ip_addresses.contains(&octets);
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.dns_names.iter().any(|name| {
            let name = name.trim_end_matches('.');
            match name.strip_prefix("*.") {
                Some(suffix) => host.split_once('.').is_some_and(|(label, rest)| {
                    !label.is_empty() && rest == suffix && suffix.contains('.')
                }),
                None => *name == host,
            }
        })
    }
}

/// Verify `signature` over `message` under `key` with `algorithm`; any
/// mismatch of key and algorithm, or malformed signature, is false.
pub fn verify(key: &SubjectKey, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> bool {
    match (key, algorithm) {
        (SubjectKey::Rsa { modulus, exponent }, Algorithm::RsaPkcs1(hash)) => {
            RsaKey::new(modulus, exponent).verify_pkcs1v15(hash, message, signature)
        }
        (SubjectKey::P256 { x, y }, Algorithm::Ecdsa(hash)) => ecdsa_der(signature)
            .is_some_and(|(r, s)| p256().verify(x, y, &hash.digest(message), r, s)),
        (SubjectKey::P384 { x, y }, Algorithm::Ecdsa(hash)) => ecdsa_der(signature)
            .is_some_and(|(r, s)| p384().verify(x, y, &hash.digest(message), r, s)),
        (SubjectKey::Ed25519(public), Algorithm::Ed25519) => <&[u8; 64]>::try_from(signature)
            .is_ok_and(|signature| crate::ed25519::verify(public, message, signature)),
        _ => false,
    }
}

/// An ECDSA signature's r and s from its DER SEQUENCE (RFC 5480 section 2.2).
pub(crate) fn ecdsa_der(signature: &[u8]) -> Option<(&[u8], &[u8])> {
    let (body, trailing) = expect(signature, SEQUENCE, "an ECDSA signature").ok()?;
    let (r, rest) = expect(body, INTEGER, "r").ok()?;
    let (s, rest) = expect(rest, INTEGER, "s").ok()?;
    (trailing.is_empty() && rest.is_empty()).then_some(())?;
    Some((unsigned(r, "r").ok()?, unsigned(s, "s").ok()?))
}

/// A Name for a message: CN and O when present, else that it has neither.
fn describe(name: &[u8]) -> String {
    let mut parts = Vec::new();
    if let Ok((mut sets, _)) = expect(name, SEQUENCE, "a name") {
        while let Ok((_, set, _, after)) = element(sets) {
            sets = after;
            if let Ok((pair, _)) = expect(set, SEQUENCE, "an attribute") {
                if let Ok((oid, rest)) = expect(pair, OID, "an attribute type") {
                    let label = match oid {
                        COMMON_NAME => "CN",
                        ORGANIZATION => "O",
                        _ => continue,
                    };
                    if let Ok((_, value, _, _)) = element(rest) {
                        parts.push(format!("{label}={}", String::from_utf8_lossy(value)));
                    }
                }
            }
        }
    }
    match parts.is_empty() {
        true => "a certificate naming no CN or O".to_string(),
        false => parts.join(", "),
    }
}

/// A trust anchor: a root's subject and key. Its own signature, validity
/// and extensions are the trust store's word and are not checked.
#[derive(Debug, Clone)]
pub struct Anchor {
    subject: Vec<u8>,
    key: SubjectKey,
}

impl Anchor {
    /// The subject and key of a root certificate.
    pub fn from_der(der: &[u8]) -> Result<Self, CertError> {
        let (certificate, _) = expect(der, SEQUENCE, "the root certificate")?;
        let (tbs, _) = expect(certificate, SEQUENCE, "the root's tbsCertificate")?;
        let mut rest = tbs;
        if rest.first() == Some(&VERSION) {
            rest = element(rest)?.3;
        }
        let rest = element(rest)?.3; // serial
        let rest = element(rest)?.3; // signature algorithm
        let rest = element(rest)?.3; // issuer
        let rest = element(rest)?.3; // validity
        let (_, _, subject, rest) = element(rest)?;
        let (info, _) = expect(rest, SEQUENCE, "the root's public key info")?;
        Ok(Anchor {
            subject: subject.to_vec(),
            key: subject_key(info)?,
        })
    }

    /// The root's subject, for a message.
    pub fn subject_name(&self) -> String {
        describe(&self.subject)
    }
}

/// Check the chain a server sent (leaf first, DER) for `host` at `now`
/// (seconds since 1970) against `anchors`, and answer the leaf's key.
pub fn verify_server_chain(
    chain: &[Vec<u8>],
    anchors: &[Anchor],
    host: &str,
    now: i64,
) -> Result<SubjectKey, CertError> {
    let Some((leaf_der, rest)) = chain.split_first() else {
        return refuse("the server sent no certificate");
    };
    if chain.len() > MAX_CHAIN {
        return refuse(format!(
            "the server sent {} certificates, past the {MAX_CHAIN} a chain is walked through",
            chain.len()
        ));
    }
    let leaf = Certificate::from_der(leaf_der)
        .map_err(|error| CertError(format!("the server's certificate cannot be read: {error}")))?;
    leaf.within(now, "server")?;
    if !leaf.names_host(host) {
        return refuse(format!(
            "the server's certificate for {} does not name {host} (it names {}): this is not the \
             server asked for, or its certificate leaves this name out",
            leaf.subject_name(),
            match (leaf.dns_names.is_empty(), leaf.ip_addresses.is_empty()) {
                (true, true) => "no DNS name or address".to_string(),
                _ => leaf.dns_names.join(", "),
            }
        ));
    }
    if leaf.server_auth == Some(false) {
        return refuse(format!(
            "the server's certificate for {} is not issued for TLS servers (its extKeyUsage lacks \
             serverAuth)",
            leaf.subject_name()
        ));
    }
    let intermediates = rest
        .iter()
        .enumerate()
        .map(|(index, der)| {
            Certificate::from_der(der).map_err(|error| {
                CertError(format!(
                    "certificate {} of the server's chain cannot be read: {error}",
                    index + 2
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut used = vec![false; intermediates.len()];
    let mut current = &leaf;
    let mut below = 0usize;
    loop {
        if anchors
            .iter()
            .any(|anchor| anchor.subject == current.issuer && current.signed_by(&anchor.key))
        {
            return Ok(leaf.key.clone());
        }
        let issuer = intermediates.iter().enumerate().find(|(index, candidate)| {
            !used[*index]
                && candidate.subject == current.issuer
                && current.signed_by(&candidate.key)
        });
        let Some((index, issuer)) = issuer else {
            let named = anchors
                .iter()
                .any(|anchor| anchor.subject == current.issuer)
                || intermediates.iter().any(|c| c.subject == current.issuer);
            return refuse(match named {
                true => format!(
                    "the certificate for {} names its issuer {}, and no certificate of that name \
                     signed it: the chain was altered or its issuer's key was replaced",
                    current.subject_name(),
                    describe(&current.issuer)
                ),
                false => format!(
                    "the certificate for {} was issued by {}, which is neither one of the {} \
                     trusted roots nor among the certificates the server sent: the server's chain \
                     is incomplete or its root is not trusted on this host",
                    current.subject_name(),
                    describe(&current.issuer),
                    anchors.len()
                ),
            });
        };
        issuer.within(now, "issuing")?;
        match issuer.ca {
            None => {
                return refuse(format!(
                    "{} signed a certificate but is not a CA (no basicConstraints cA)",
                    issuer.subject_name()
                ))
            }
            Some(limit) if limit < below => {
                return refuse(format!(
                "{} may have {limit} CA certificates below it (pathLenConstraint) and has {below}",
                issuer.subject_name()
            ))
            }
            Some(_) => {}
        }
        if issuer.key_cert_sign == Some(false) {
            return refuse(format!(
                "{} signed a certificate but its keyUsage lacks keyCertSign",
                issuer.subject_name()
            ));
        }
        used[index] = true;
        below += 1;
        current = issuer;
    }
}
