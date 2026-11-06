//! Readers for the official vector files under tests/vectors, taken verbatim
//! from NIST CAVP and the RFCs.
#![allow(dead_code, reason = "each test binary uses the readers it needs")]

use std::collections::BTreeMap;
use std::path::PathBuf;

pub fn vector_file(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

pub fn hex(text: &str) -> Vec<u8> {
    let text = text.trim();
    let text = text.strip_prefix("0x").unwrap_or(text);
    let text: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    assert!(text.len().is_multiple_of(2), "odd hex: {text}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One record of a CAVP .rsp file: its section (`[ENCRYPT]`, `[L = 32]`)
/// and its `NAME = value` fields.
pub struct Record {
    pub section: String,
    pub fields: BTreeMap<String, String>,
}

impl Record {
    pub fn get(&self, name: &str) -> &str {
        self.fields.get(name).unwrap_or_else(|| {
            panic!(
                "record in {} has no {name}: {:?}",
                self.section, self.fields
            )
        })
    }
}

/// Every record of a CAVP .rsp file, in order. A record ends at a blank line.
pub fn rsp(relative: &str) -> Vec<Record> {
    let text = vector_file(relative);
    let mut records = Vec::new();
    let mut section = String::new();
    let mut fields = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !fields.is_empty() {
                records.push(Record {
                    section: section.clone(),
                    fields: std::mem::take(&mut fields),
                });
            }
            continue;
        }
        if line.starts_with('[') {
            section = line.to_string();
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            fields.insert(name.trim().to_string(), value.trim().to_string());
        }
    }
    if !fields.is_empty() {
        records.push(Record { section, fields });
    }
    records
}

/// The lines of an RFC text with page breaks (form feeds, the page footer
/// and the next page's header) removed, so a value split across pages reads
/// as one.
pub fn rfc_lines(relative: &str) -> Vec<String> {
    let text = vector_file(relative);
    let mut lines = Vec::new();
    let mut skipping_header = false;
    for line in text.lines() {
        if line.contains('\u{c}') {
            skipping_header = true;
            continue;
        }
        if skipping_header {
            if line.starts_with("RFC ") {
                skipping_header = false;
            }
            continue;
        }
        if line.contains("[Page ") {
            continue;
        }
        lines.push(line.to_string());
    }
    lines
}

/// The `Name = value` (or `Name: value`) fields of RFC text from `start` up
/// to the first line after it that `end` matches, in order. A field's value
/// continues on following lines of hex; anything in parentheses is the
/// RFC's annotation and is dropped. Values are the text as written; read
/// hex ones with [`hex`].
pub fn labelled(
    lines: &[String],
    start: usize,
    end: impl Fn(&str) -> bool,
) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut open = false;
    for (index, line) in lines.iter().enumerate().skip(start) {
        if index > start && end(line) {
            break;
        }
        let bare = match line.find('(') {
            Some(at) => &line[..at],
            None => line.as_str(),
        };
        let trimmed = bare.trim();
        if trimmed.is_empty() {
            open = false;
            continue;
        }
        let split = trimmed
            .find(" = ")
            .map(|at| (at, 3))
            .or_else(|| trimmed.find(": ").map(|at| (at, 2)));
        let split = split.or_else(|| trimmed.strip_suffix(':').map(|label| (label.len(), 1)));
        // RFC 4231 test case 3 writes `Key            aaaa…` with no `=`.
        let split = split.or_else(|| {
            let mut words = trimmed.split_whitespace();
            let label = words.next()?;
            let rest: Vec<&str> = words.collect();
            let hexlike = |w: &str| w.chars().all(|c| c.is_ascii_hexdigit());
            (!open && !hexlike(label) && rest.len() == 1 && hexlike(rest[0]))
                .then_some((label.len(), 0))
        });
        match split {
            Some((at, width)) => {
                fields.push((
                    trimmed[..at].trim().to_string(),
                    trimmed[at + width..].trim().to_string(),
                ));
                open = true;
            }
            None if open && trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == ' ') => {
                if let Some(last) = fields.last_mut() {
                    last.1.push_str(trimmed);
                }
            }
            None => open = false,
        }
    }
    fields
}

/// The first line index at or after `from` that `matches` accepts.
pub fn find_line(lines: &[String], from: usize, matches: impl Fn(&str) -> bool) -> usize {
    (from..lines.len())
        .find(|&i| matches(&lines[i]))
        .unwrap_or_else(|| panic!("no line after {from} matched"))
}
