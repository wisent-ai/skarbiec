//! The public keys a GnuPG home holds, read from its files without running
//! anything: keyboxd's `public-keys.d/pubring.db` (an SQLite database whose
//! `pubkey` table holds each OpenPGP keyblock) and the older keybox file
//! `pubring.kbx`. Only reading: the SQLite file format (b-tree pages,
//! overflow pages, records) as sqlite.org/fileformat2.html defines it, and
//! the keybox blob layout of GnuPG's kbx/keybox-blob.c.

use super::{malformed, Error};

/// One OpenPGP keyblock and whether the store marks it revoked.
pub struct StoredKey {
    pub keyblock: Vec<u8>,
    pub revoked: bool,
}

fn be16(data: &[u8], at: usize) -> Result<usize, Error> {
    data.get(at..at + 2)
        .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
        .ok_or_else(|| malformed("the key database is cut short"))
}

fn be32(data: &[u8], at: usize) -> Result<usize, Error> {
    data.get(at..at + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
        .ok_or_else(|| malformed("the key database is cut short"))
}

/// An SQLite varint at `at`: its value and length.
fn varint(data: &[u8], at: usize) -> Result<(u64, usize), Error> {
    let mut value = 0u64;
    for i in 0..9 {
        let byte = *data
            .get(at + i)
            .ok_or_else(|| malformed("a database varint is cut short"))?;
        if i == 8 {
            return Ok(((value << 8) | u64::from(byte), 9));
        }
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    unreachable!("the loop returns by its ninth byte")
}

struct Database<'a> {
    file: &'a [u8],
    page_size: usize,
    usable: usize,
}

impl<'a> Database<'a> {
    fn open(file: &'a [u8]) -> Result<Self, Error> {
        if file.get(..16) != Some(b"SQLite format 3\0") {
            return Err(malformed("the key database is not an SQLite 3 file"));
        }
        let page_size = match be16(file, 16)? {
            1 => 65_536,
            n => n,
        };
        let reserved = usize::from(file[20]);
        if page_size < 512 || page_size <= reserved {
            return Err(malformed("the key database has an impossible page size"));
        }
        Ok(Self {
            file,
            page_size,
            usable: page_size - reserved,
        })
    }

    fn page(&self, number: usize) -> Result<&'a [u8], Error> {
        if number == 0 {
            return Err(malformed("a database page number is zero"));
        }
        let start = (number - 1) * self.page_size;
        self.file.get(start..start + self.page_size).ok_or_else(|| {
            malformed(format!(
                "database page {number} is past the end of the file"
            ))
        })
    }

    /// The payload of every row of the table b-tree rooted at `root`.
    fn rows(&self, root: usize) -> Result<Vec<Vec<u8>>, Error> {
        let mut out = Vec::new();
        let mut stack = vec![root];
        let mut visited = 0usize;
        while let Some(number) = stack.pop() {
            visited += 1;
            if visited > self.file.len() / self.page_size + 1 {
                return Err(malformed("the key database's b-tree loops"));
            }
            let page = self.page(number)?;
            let header = if number == 1 { 100 } else { 0 };
            let kind = page[header];
            let cells = be16(page, header + 3)?;
            let pointers = header + if kind == 0x05 { 12 } else { 8 };
            match kind {
                0x05 => {
                    stack.push(be32(page, header + 8)?);
                    for i in 0..cells {
                        let cell = be16(page, pointers + 2 * i)?;
                        stack.push(be32(page, cell)?);
                    }
                }
                0x0d => {
                    for i in 0..cells {
                        let cell = be16(page, pointers + 2 * i)?;
                        out.push(self.leaf_payload(page, cell)?);
                    }
                }
                other => {
                    return Err(malformed(format!(
                        "database page {number} has b-tree type {other:#04x}"
                    )))
                }
            }
        }
        Ok(out)
    }

    fn leaf_payload(&self, page: &[u8], cell: usize) -> Result<Vec<u8>, Error> {
        let (size, a) = varint(page, cell)?;
        let (_, b) = varint(page, cell + a)?;
        let size = size as usize;
        let start = cell + a + b;
        let u = self.usable;
        let x = u - 35;
        let local = if size <= x {
            size
        } else {
            let m = ((u - 12) * 32 / 255) - 23;
            let k = m + ((size - m) % (u - 4));
            if k <= x {
                k
            } else {
                m
            }
        };
        let mut payload = page
            .get(start..start + local)
            .ok_or_else(|| malformed("a database cell is cut short"))?
            .to_vec();
        if local < size {
            let mut next = be32(page, start + local)?;
            while payload.len() < size {
                let overflow = self.page(next)?;
                next = be32(overflow, 0)?;
                let take = (size - payload.len()).min(u - 4);
                payload.extend_from_slice(&overflow[4..4 + take]);
            }
        }
        Ok(payload)
    }
}

/// A record's column values: integers, and text or blob bytes.
#[derive(Debug)]
enum Value {
    Null,
    Integer(i64),
    Bytes(Vec<u8>),
}

fn record(payload: &[u8]) -> Result<Vec<Value>, Error> {
    let (header_size, mut at) = varint(payload, 0)?;
    let mut types = Vec::new();
    while at < header_size as usize {
        let (serial, n) = varint(payload, at)?;
        types.push(serial);
        at += n;
    }
    let mut body = header_size as usize;
    let mut out = Vec::new();
    for serial in types {
        let take = |n: usize, body: &mut usize| -> Result<&[u8], Error> {
            let bytes = payload
                .get(*body..*body + n)
                .ok_or_else(|| malformed("a database record is cut short"))?;
            *body += n;
            Ok(bytes)
        };
        let int = |bytes: &[u8]| -> i64 {
            let mut value: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
            for &b in bytes {
                value = (value << 8) | i64::from(b);
            }
            value
        };
        out.push(match serial {
            0 => Value::Null,
            1 => Value::Integer(int(take(1, &mut body)?)),
            2 => Value::Integer(int(take(2, &mut body)?)),
            3 => Value::Integer(int(take(3, &mut body)?)),
            4 => Value::Integer(int(take(4, &mut body)?)),
            5 => Value::Integer(int(take(6, &mut body)?)),
            6 => Value::Integer(int(take(8, &mut body)?)),
            7 => {
                take(8, &mut body)?;
                Value::Null
            }
            8 => Value::Integer(0),
            9 => Value::Integer(1),
            n if n >= 12 => Value::Bytes(take(((n - 12) / 2) as usize, &mut body)?.to_vec()),
            n => {
                return Err(malformed(format!(
                    "a database record has reserved serial type {n}"
                )))
            }
        });
    }
    Ok(out)
}

/// Every OpenPGP keyblock in keyboxd's `pubring.db`.
pub fn read_pubring_db(file: &[u8]) -> Result<Vec<StoredKey>, Error> {
    let db = Database::open(file)?;
    let mut root = None;
    for row in db.rows(1)? {
        let columns = record(&row)?;
        if let (Some(Value::Bytes(kind)), Some(Value::Bytes(name)), Some(Value::Integer(page))) =
            (columns.first(), columns.get(1), columns.get(3))
        {
            if kind == b"table" && name == b"pubkey" {
                root = Some(*page as usize);
            }
        }
    }
    let root = root.ok_or_else(|| malformed("the key database has no pubkey table"))?;
    let mut keys = Vec::new();
    for row in db.rows(root)? {
        // pubkey (ubid, type, ephemeral, revoked, keyblob); type 1 is OpenPGP.
        let columns = record(&row)?;
        let kind = match columns.get(1) {
            Some(Value::Integer(kind)) => *kind,
            _ => return Err(malformed("a pubkey row has no type")),
        };
        let revoked = matches!(columns.get(3), Some(Value::Integer(1)));
        let Some(Value::Bytes(keyblock)) = columns.get(4) else {
            return Err(malformed("a pubkey row has no keyblob"));
        };
        if kind == 1 {
            keys.push(StoredKey {
                keyblock: keyblock.clone(),
                revoked,
            });
        }
    }
    Ok(keys)
}

/// Every OpenPGP keyblock in a keybox file (`pubring.kbx`).
pub fn read_keybox(file: &[u8]) -> Result<Vec<StoredKey>, Error> {
    let mut keys = Vec::new();
    let mut at = 0;
    while at < file.len() {
        let length = be32(file, at)?;
        if length < 5 || at + length > file.len() {
            return Err(malformed("a keybox blob has an impossible length"));
        }
        let blob = &file[at..at + length];
        // Type 2 is an OpenPGP blob: version, flags, keyblock offset and length.
        if blob[4] == 2 {
            let offset = be32(blob, 8)?;
            let len = be32(blob, 12)?;
            let keyblock = blob
                .get(offset..offset + len)
                .ok_or_else(|| malformed("a keybox blob's keyblock is out of range"))?;
            keys.push(StoredKey {
                keyblock: keyblock.to_vec(),
                revoked: false,
            });
        }
        at += length;
    }
    Ok(keys)
}
