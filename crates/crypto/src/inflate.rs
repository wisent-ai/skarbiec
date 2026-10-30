//! Inflate (RFC 1951) and the zlib wrapper (RFC 1950): what OpenPGP's
//! compressed data packet holds. Only decompression is here; nothing new is
//! compressed. The data is the plaintext of a message that already opened,
//! so it is not secret from the reader, and every limit below is the
//! format's own.

/// Why a stream did not inflate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InflateError(pub String);

impl std::fmt::Display for InflateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "the compressed data is damaged: {}", self.0)
    }
}

impl std::error::Error for InflateError {}

fn damaged(why: impl Into<String>) -> InflateError {
    InflateError(why.into())
}

struct Bits<'a> {
    data: &'a [u8],
    at: usize,
    bit: u32,
}

impl Bits<'_> {
    fn take(&mut self, count: u32) -> Result<u32, InflateError> {
        let mut value = 0u32;
        for i in 0..count {
            let byte = *self
                .data
                .get(self.at)
                .ok_or_else(|| damaged("it ends in the middle of a block"))?;
            value |= u32::from((byte >> self.bit) & 1) << i;
            self.bit += 1;
            if self.bit == 8 {
                self.bit = 0;
                self.at += 1;
            }
        }
        Ok(value)
    }

    fn align(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.at += 1;
        }
    }
}

/// A canonical Huffman code: how many codes of each length, and the symbols
/// in code order (RFC 1951 section 3.2.2).
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Self, InflateError> {
        let mut counts = [0u16; 16];
        for &length in lengths {
            counts[usize::from(length)] += 1;
        }
        counts[0] = 0;
        let mut left = 1i32;
        for count in counts.iter().skip(1) {
            left = left * 2 - i32::from(*count);
            if left < 0 {
                return Err(damaged(
                    "a Huffman code has more codes than its lengths allow",
                ));
            }
        }
        let mut offsets = [0u16; 16];
        for length in 1..16 {
            offsets[length] = offsets[length - 1] + counts[length - 1];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (symbol, &length) in lengths.iter().enumerate() {
            if length != 0 {
                symbols[usize::from(offsets[usize::from(length)])] = symbol as u16;
                offsets[usize::from(length)] += 1;
            }
        }
        Ok(Self { counts, symbols })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, InflateError> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for length in 1..16 {
            code |= bits.take(1)? as i32;
            let count = i32::from(self.counts[length]);
            if code - count < first {
                return Ok(self.symbols[(index + (code - first)) as usize]);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(damaged("a Huffman code is longer than 15 bits"))
    }
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// The order the code length code lengths are sent in (RFC 1951 3.2.7).
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn fixed_codes() -> Result<(Huffman, Huffman), InflateError> {
    let mut lengths = [0u8; 288];
    lengths[..144].fill(8);
    lengths[144..256].fill(9);
    lengths[256..280].fill(7);
    lengths[280..].fill(8);
    Ok((Huffman::new(&lengths)?, Huffman::new(&[5u8; 30])?))
}

fn dynamic_codes(bits: &mut Bits<'_>) -> Result<(Huffman, Huffman), InflateError> {
    let literals = bits.take(5)? as usize + 257;
    let distances = bits.take(5)? as usize + 1;
    let code_lengths = bits.take(4)? as usize + 4;
    if literals > 286 || distances > 30 {
        return Err(damaged(
            "a dynamic block declares more codes than deflate has",
        ));
    }
    let mut order = [0u8; 19];
    for &position in CODE_LENGTH_ORDER.iter().take(code_lengths) {
        order[position] = bits.take(3)? as u8;
    }
    let length_code = Huffman::new(&order)?;
    let mut lengths = vec![0u8; literals + distances];
    let mut i = 0;
    while i < lengths.len() {
        let symbol = length_code.decode(bits)?;
        let (value, repeat) = match symbol {
            0..=15 => (symbol as u8, 1),
            16 => {
                let previous = *lengths[..i]
                    .last()
                    .ok_or_else(|| damaged("a repeat has no previous length"))?;
                (previous, 3 + bits.take(2)? as usize)
            }
            17 => (0, 3 + bits.take(3)? as usize),
            18 => (0, 11 + bits.take(7)? as usize),
            _ => return Err(damaged("a code length symbol is out of range")),
        };
        if i + repeat > lengths.len() {
            return Err(damaged("code lengths run past their count"));
        }
        lengths[i..i + repeat].fill(value);
        i += repeat;
    }
    if lengths[256] == 0 {
        return Err(damaged("a dynamic block has no end-of-block code"));
    }
    Ok((
        Huffman::new(&lengths[..literals])?,
        Huffman::new(&lengths[literals..])?,
    ))
}

/// Inflate a raw deflate stream (RFC 1951). Bytes after its last block are
/// returned as the second value, so a wrapper can read its trailer.
pub fn inflate(data: &[u8]) -> Result<(Vec<u8>, usize), InflateError> {
    let mut bits = Bits {
        data,
        at: 0,
        bit: 0,
    };
    let mut out: Vec<u8> = Vec::new();
    loop {
        let last = bits.take(1)? == 1;
        match bits.take(2)? {
            0 => {
                bits.align();
                let header = data
                    .get(bits.at..bits.at + 4)
                    .ok_or_else(|| damaged("a stored block has no length"))?;
                let length = u16::from_le_bytes([header[0], header[1]]);
                let check = u16::from_le_bytes([header[2], header[3]]);
                if length != !check {
                    return Err(damaged(
                        "a stored block's length and its complement disagree",
                    ));
                }
                bits.at += 4;
                let body = data
                    .get(bits.at..bits.at + usize::from(length))
                    .ok_or_else(|| damaged("a stored block is shorter than its length"))?;
                out.extend_from_slice(body);
                bits.at += usize::from(length);
            }
            kind @ (1 | 2) => {
                let (literal, distance) = if kind == 1 {
                    fixed_codes()?
                } else {
                    dynamic_codes(&mut bits)?
                };
                loop {
                    let symbol = literal.decode(&mut bits)?;
                    match symbol {
                        0..=255 => out.push(symbol as u8),
                        256 => break,
                        257..=285 => {
                            let index = usize::from(symbol - 257);
                            let length = usize::from(LENGTH_BASE[index])
                                + bits.take(u32::from(LENGTH_EXTRA[index]))? as usize;
                            let code = usize::from(distance.decode(&mut bits)?);
                            if code >= 30 {
                                return Err(damaged("a distance code is out of range"));
                            }
                            let back = usize::from(DISTANCE_BASE[code])
                                + bits.take(u32::from(DISTANCE_EXTRA[code]))? as usize;
                            if back > out.len() {
                                return Err(damaged(
                                    "a match reaches before the start of the data",
                                ));
                            }
                            let start = out.len() - back;
                            for k in 0..length {
                                out.push(out[start + k]);
                            }
                        }
                        _ => return Err(damaged("a literal/length code is out of range")),
                    }
                }
            }
            _ => return Err(damaged("a block has the reserved type 3")),
        }
        if last {
            break;
        }
    }
    bits.align();
    Ok((out, bits.at))
}

/// Adler-32 (RFC 1950 section 8).
pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= 65_521;
        b %= 65_521;
    }
    (b << 16) | a
}

/// Inflate a zlib stream (RFC 1950): header, deflate data, Adler-32.
pub fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>, InflateError> {
    let (cmf, flags) = match data {
        [cmf, flags, ..] => (*cmf, *flags),
        _ => return Err(damaged("the zlib header is missing")),
    };
    if cmf & 0x0f != 8 {
        return Err(damaged(format!(
            "the zlib method is {}, not deflate (8)",
            cmf & 0x0f
        )));
    }
    if (u16::from(cmf) << 8 | u16::from(flags)) % 31 != 0 {
        return Err(damaged("the zlib header check fails"));
    }
    if flags & 0x20 != 0 {
        return Err(damaged("the zlib stream needs a preset dictionary"));
    }
    let (out, used) = inflate(&data[2..])?;
    let trailer = data
        .get(2 + used..2 + used + 4)
        .ok_or_else(|| damaged("the zlib Adler-32 trailer is missing"))?;
    let expected = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    if adler32(&out) != expected {
        return Err(damaged("the zlib Adler-32 does not match the data"));
    }
    Ok(out)
}
