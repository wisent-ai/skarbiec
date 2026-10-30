//! ASCII armor (RFC 4880 section 6): radix-64 with a CRC-24 checksum.

use super::Error;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// CRC-24 (RFC 4880 section 6.1).
pub fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0x00b7_04ce;
    for &byte in data {
        crc ^= u32::from(byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4cfb;
            }
        }
    }
    crc & 0x00ff_ffff
}

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn base64_decode(text: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0;
    for c in text.bytes() {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        let value = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| Error::Armor(format!("{:?} is not a radix-64 character", c as char)))?;
        accumulator = (accumulator << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    Ok(out)
}

/// The body of the first armored block of `kind` (`PGP MESSAGE`, `PGP
/// PUBLIC KEY BLOCK`, `PGP SIGNATURE`) in `text`, its checksum verified when
/// it has one.
pub fn dearmor(text: &str, kind: &str) -> Result<Vec<u8>, Error> {
    let begin = format!("-----BEGIN {kind}-----");
    let end = format!("-----END {kind}-----");
    let start = text
        .find(&begin)
        .ok_or_else(|| Error::Armor(format!("there is no {begin} line")))?;
    let rest = &text[start + begin.len()..];
    let stop = rest
        .find(&end)
        .ok_or_else(|| Error::Armor(format!("there is no {end} line")))?;
    let block = &rest[..stop];
    // Armor headers run to the first blank line.
    let mut lines = block.lines().skip(1).peekable();
    let has_headers = block
        .lines()
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .any(|l| l.contains(": "));
    if has_headers {
        for line in lines.by_ref() {
            if line.trim().is_empty() {
                break;
            }
        }
    }
    let mut body = String::new();
    let mut checksum = None;
    for line in lines {
        let line = line.trim();
        if let Some(sum) = line.strip_prefix('=').filter(|s| s.len() == 4) {
            checksum = Some(sum.to_string());
        } else {
            body.push_str(line);
        }
    }
    let data = base64_decode(&body)?;
    if let Some(sum) = checksum {
        let expected = base64_decode(&sum)?;
        let expected =
            (u32::from(expected[0]) << 16) | (u32::from(expected[1]) << 8) | u32::from(expected[2]);
        if crc24(&data) != expected {
            return Err(Error::Armor(format!(
                "the {kind} armor's CRC-24 does not match its data: it was changed or cut"
            )));
        }
    }
    Ok(data)
}

/// `data` armored as `kind`, in 64-character lines with its CRC-24.
pub fn armor(data: &[u8], kind: &str) -> String {
    let mut out = format!("-----BEGIN {kind}-----\n\n");
    let encoded = base64_encode(data);
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("radix-64 is ASCII"));
        out.push('\n');
    }
    let crc = crc24(data);
    out.push('=');
    out.push_str(&base64_encode(&[
        (crc >> 16) as u8,
        (crc >> 8) as u8,
        crc as u8,
    ]));
    out.push('\n');
    out.push_str(&format!("-----END {kind}-----\n"));
    out
}
