//! Inflate and zlib against streams written by the real tools, compared
//! with the bytes they compressed: GnuPG's ZLIB compressed data packets
//! (`gpg --compress-algo zlib -z 1|6|9 --store`, the packet stored items
//! carry) and gzip's raw deflate at levels 1, 6 and 9, for an empty input,
//! one byte, RFC 1951's own text, 70,000 random bytes (stored blocks) and a
//! repeated phrase (long matches). Damaged streams are refused.

mod common;

use skarbiec_crypto::inflate::{adler32, inflate, zlib_decompress};
use std::path::PathBuf;

fn read(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/inflate")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

const INPUTS: [&str; 5] = ["empty", "one", "text", "random", "repeated"];
const LEVELS: [u8; 3] = [1, 6, 9];

/// The zlib stream inside a GnuPG compressed data packet written with an
/// old-format, indeterminate-length header (`a3`) and algorithm 2.
fn zlib_in_packet(packet: &[u8]) -> &[u8] {
    assert_eq!(
        &packet[..2],
        &[0xa3, 0x02],
        "a compressed data packet of algorithm ZLIB"
    );
    &packet[2..]
}

/// The raw deflate data of a gzip member with no optional fields.
fn deflate_in_gzip(member: &[u8]) -> &[u8] {
    assert_eq!(
        &member[..4],
        &[0x1f, 0x8b, 0x08, 0x00],
        "a gzip member with no flags"
    );
    &member[10..member.len() - 8]
}

#[test]
fn zlib_from_gnupg() {
    for input in INPUTS {
        let expected = read(&format!("{input}.bin"));
        for level in LEVELS {
            let packet = read(&format!("{input}.{level}.gpg"));
            let inner = zlib_decompress(zlib_in_packet(&packet), LIMIT).expect("inflates");
            // Inside is a literal data packet; its body ends the stream.
            assert!(
                inner.ends_with(&expected),
                "{input} at level {level}: the literal data is not the input"
            );
        }
    }
}

#[test]
fn deflate_from_gzip() {
    for input in INPUTS {
        let expected = read(&format!("{input}.bin"));
        for level in LEVELS {
            let member = read(&format!("{input}.{level}.gz"));
            let (out, _) = inflate(deflate_in_gzip(&member), LIMIT).expect("inflates");
            assert_eq!(out, expected, "{input} at level {level}");
        }
    }
}

/// Adler-32 of the empty string is its initial value 1 (RFC 1950 section
/// 8); every gpg and gzip stream above also checks it against zlib's own.
/// "Wikipedia" is the widely published worked example, 0x11E60398.
#[test]
fn adler32_reference() {
    assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
    assert_eq!(adler32(b""), 1);
}

#[test]
fn damaged_streams_are_refused() {
    let packet = read("text.6.gpg");
    let zlib = zlib_in_packet(&packet);
    let short = zlib_decompress(&zlib[..zlib.len() / 2], LIMIT).expect_err("truncated");
    assert_eq!(
        short.to_string(),
        "the compressed data is damaged: it ends in the middle of a block"
    );
    let mut wrong_sum = zlib.to_vec();
    let last = wrong_sum.len() - 1;
    wrong_sum[last] ^= 1;
    assert_eq!(
        zlib_decompress(&wrong_sum, LIMIT)
            .expect_err("bad Adler-32")
            .to_string(),
        "the compressed data is damaged: the zlib Adler-32 does not match the data"
    );
    let mut wrong_method = zlib.to_vec();
    wrong_method[0] = 0x77;
    assert!(zlib_decompress(&wrong_method, LIMIT)
        .expect_err("method")
        .to_string()
        .contains("not deflate (8)"));
    assert_eq!(
        zlib_decompress(&[], LIMIT).expect_err("empty").to_string(),
        "the compressed data is damaged: the zlib header is missing"
    );
    assert_eq!(
        inflate(&[0x07], LIMIT).expect_err("reserved").to_string(),
        "the compressed data is damaged: a block has the reserved type 3"
    );
}

/// A stream that inflates past its limit is refused at the limit, not
/// grown: a fixed-Huffman block of one literal then back-references of 258
/// bytes at distance 1, each a few bits, asks for far more than its size.
#[test]
fn a_stream_past_its_limit_is_refused() {
    // Fixed codes (BTYPE 01), final block: literal 'a', then length 258
    // (symbol 285, code 11000101) at distance 1 (code 00000), repeated.
    let mut bits: Vec<u8> = vec![1, 1, 0];
    let push = |bits: &mut Vec<u8>, code: u32, width: u32| {
        for i in (0..width).rev() {
            bits.push(((code >> i) & 1) as u8);
        }
    };
    push(&mut bits, 0x30 + u32::from(b'a'), 8);
    for _ in 0..4000 {
        push(&mut bits, 0b1100_0101, 8);
        push(&mut bits, 0, 5);
    }
    push(&mut bits, 0, 7);
    let mut stream = vec![0u8; bits.len().div_ceil(8)];
    for (i, bit) in bits.iter().enumerate() {
        stream[i / 8] |= bit << (i % 8);
    }
    let (out, _) = inflate(&stream, 2_000_000).expect("inflates within a large limit");
    assert_eq!(out.len(), 1 + 4000 * 258);
    assert_eq!(
        inflate(&stream, 100_000).expect_err("past the limit").to_string(),
        "the compressed data is damaged: the stream inflates past 100000 bytes, the most this reader takes"
    );
}

/// The limit the tests open real streams with: far above any of them.
const LIMIT: usize = 1 << 24;
