//! What `certificates` reads from an X.509 certificate (RFC 5280), in this
//! process: its subject, its issuer and the end of its validity. Only the
//! DER structure up to those fields is read; nothing is verified, as the
//! report is about when a certificate ends, not whether to trust it.
//!
//! Names are written as RFC 4514 strings (the successor of RFC 2253, the
//! form the report has always used): the relative distinguished names in
//! reverse order, separated by commas, each attribute as `TYPE=value` with
//! the characters RFC 4514 section 2.4 names escaped.

use anyhow::{bail, Context, Result};

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// The DER of the first PEM certificate in `pem`.
pub(super) fn first_pem(pem: &str) -> Result<Vec<u8>> {
    let start = pem.find(PEM_BEGIN).with_context(|| {
        format!("the text holds no {PEM_BEGIN} line, so it is not a PEM certificate")
    })?;
    let rest = &pem[start + PEM_BEGIN.len()..];
    let end = rest
        .find(PEM_END)
        .with_context(|| format!("the certificate has no {PEM_END} line; it was cut short"))?;
    let body: String = rest[..end].split_whitespace().collect();
    skarbiec_crypto::openpgp::armor::base64_decode(&body)
        .map_err(|error| anyhow::anyhow!("the certificate's base64 does not decode: {error}"))
}

/// One DER element: its tag, its contents, and what follows it.
fn element(data: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first().context("a DER element is missing")?;
    let (&first, rest) = rest.split_first().context("a DER element has no length")?;
    let (length, rest) = if first & 0x80 == 0 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            bail!("a DER length is malformed");
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |sum, byte| (sum << 8) | usize::from(*byte));
        (length, &rest[count..])
    };
    if rest.len() < length {
        bail!("a DER element runs past the end of the certificate");
    }
    Ok((tag, &rest[..length], &rest[length..]))
}

fn expect<'a>(data: &'a [u8], tag: u8, what: &str) -> Result<(&'a [u8], &'a [u8])> {
    let (found, contents, rest) = element(data).with_context(|| format!("read the {what}"))?;
    if found != tag {
        bail!("the {what} has DER tag {found:#04x}, not {tag:#04x}");
    }
    Ok((contents, rest))
}

/// The dotted form of an OBJECT IDENTIFIER's contents.
fn dotted(oid: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut value: u64 = 0;
    for byte in oid {
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            // The first sub-identifier carries the first two arcs (X.690 8.19.4).
            if parts.is_empty() {
                let first = (value / 40).min(2);
                parts.push(first);
                parts.push(value - first * 40);
            } else {
                parts.push(value);
            }
            value = 0;
        }
    }
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// The short name OpenSSL and RFC 4514 give an attribute type.
fn short_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.42" => "GN",
        "2.5.4.97" => "organizationIdentifier",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "1.3.6.1.4.1.311.60.2.1.3" => "jurisdictionC",
        "2.5.4.15" => "businessCategory",
        _ => return None,
    })
}

/// RFC 4514 section 2.4 escaping of an attribute value.
fn escape(value: &str) -> String {
    let mut out = String::new();
    let last = value.chars().count().saturating_sub(1);
    for (index, c) in value.chars().enumerate() {
        let leading = index == 0 && (c == ' ' || c == '#');
        let trailing = index == last && c == ' ';
        if leading || trailing || matches!(c, '"' | '+' | ',' | ';' | '<' | '>' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A Name (RFC 5280 section 4.1.2.4) as an RFC 4514 string.
fn name(contents: &[u8]) -> Result<String> {
    let mut rdns = Vec::new();
    let mut rest = contents;
    while !rest.is_empty() {
        let (set, after) = expect(rest, 0x31, "relative distinguished name")?;
        rest = after;
        let mut attributes = Vec::new();
        let mut inner = set;
        while !inner.is_empty() {
            let (pair, after) = expect(inner, 0x30, "name attribute")?;
            inner = after;
            let (oid, value) = expect(pair, 0x06, "attribute type")?;
            let (tag, text, _) = element(value).context("read an attribute value")?;
            let oid = dotted(oid);
            let rendered = match (short_name(&oid), tag) {
                // UTF8String, PrintableString, IA5String, TeletexString
                // (read as Latin-1, what it holds in practice), BMPString.
                (Some(short), 0x0c | 0x13 | 0x16) => {
                    format!("{short}={}", escape(&String::from_utf8_lossy(text)))
                }
                (Some(short), 0x14) => format!(
                    "{short}={}",
                    escape(&text.iter().map(|b| char::from(*b)).collect::<String>())
                ),
                (Some(short), 0x1e) => {
                    let units: Vec<u16> = text
                        .chunks(2)
                        .map(|pair| u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]))
                        .collect();
                    format!("{short}={}", escape(&String::from_utf16_lossy(&units)))
                }
                // RFC 4514: a type without a short name, or a value of
                // another syntax, is the dotted type and the value's DER in hex.
                _ => format!("{oid}=#{}", hex(value)),
            };
            attributes.push(rendered);
        }
        rdns.push(attributes.join("+"));
    }
    rdns.reverse();
    Ok(rdns.join(","))
}

/// A UTCTime or GeneralizedTime as `YYYY-MM-DDTHH:MM:SSZ`.
fn time(tag: u8, contents: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(contents).context("a validity time is not ASCII")?;
    let digits = text
        .strip_suffix('Z')
        .context("a validity time is not stated in UTC (Z), as RFC 5280 requires")?;
    let (year, rest) = match tag {
        0x17 if digits.len() == 12 => {
            let short: u32 = digits[..2]
                .parse()
                .context("a UTCTime year is not a number")?;
            // RFC 5280 section 4.1.2.5.1: 50 and later is 19YY.
            (
                if short >= 50 {
                    1900 + short
                } else {
                    2000 + short
                },
                &digits[2..],
            )
        }
        0x18 if digits.len() == 14 => (
            digits[..4]
                .parse()
                .context("a GeneralizedTime year is not a number")?,
            &digits[4..],
        ),
        _ => bail!("a validity time {text:?} is not a UTCTime or GeneralizedTime RFC 5280 allows"),
    };
    if !rest.chars().all(|c| c.is_ascii_digit()) {
        bail!("a validity time {text:?} holds a character that is not a digit");
    }
    Ok(format!(
        "{year:04}-{}-{}T{}:{}:{}Z",
        &rest[0..2],
        &rest[2..4],
        &rest[4..6],
        &rest[6..8],
        &rest[8..10]
    ))
}

/// The subject, issuer and end of validity of a DER certificate.
pub(super) fn facts(der: &[u8]) -> Result<(String, String, String)> {
    let (certificate, _) = expect(der, 0x30, "certificate")?;
    let (tbs, _) = expect(certificate, 0x30, "certificate body")?;
    let mut rest = tbs;
    // version [0] EXPLICIT, present for v2 and v3 certificates.
    if rest.first() == Some(&0xa0) {
        let (_, _, after) = element(rest)?;
        rest = after;
    }
    let (_serial, _, after) = element(rest).context("read the serial number")?;
    rest = after;
    let (_, after) = expect(rest, 0x30, "signature algorithm")?;
    rest = after;
    let (issuer, after) = expect(rest, 0x30, "issuer")?;
    rest = after;
    let (validity, after) = expect(rest, 0x30, "validity")?;
    rest = after;
    let (subject, _) = expect(rest, 0x30, "subject")?;
    let (_not_before_tag, _, after) = element(validity).context("read notBefore")?;
    let (tag, not_after, _) = element(after).context("read notAfter")?;
    Ok((name(subject)?, name(issuer)?, time(tag, not_after)?))
}
