//! The `ProgramArguments` a launch agent declares, read from its property
//! list in process: the XML form launchd agents are written in, and the
//! binary form (`bplist00`) a plist takes once an editor has saved it.

use anyhow::{Context, Result};
use std::path::Path;

/// The unit's argv, as its launch agent declares it.
pub(super) fn program_arguments(plist: &Path) -> Result<Vec<String>> {
    let bytes = std::fs::read(plist)
        .with_context(|| format!("read the launch agent {}", plist.display()))?;
    let found = if bytes.starts_with(b"bplist00") {
        binary::program_arguments(&bytes)
    } else {
        let text =
            std::str::from_utf8(&bytes).context("it is neither a binary plist nor UTF-8 text")?;
        xml::program_arguments(text)
    };
    found.with_context(|| {
        format!(
            "the launch agent {} declares no readable ProgramArguments; it must be a property list \
             whose top-level dict holds ProgramArguments, an array of strings",
            plist.display()
        )
    })
}

mod xml {
    use anyhow::{bail, Context, Result};

    /// One element of the document: its name and whether it opens, closes,
    /// or is both (`<true/>`), with the text before the next one.
    struct Cursor<'a> {
        text: &'a str,
        at: usize,
    }

    enum Tag<'a> {
        Open(&'a str),
        Close(&'a str),
        Empty(&'a str),
    }

    impl<'a> Cursor<'a> {
        /// The next tag, skipping the declaration, the doctype and comments;
        /// the text before it is what `text_until_tag` reads.
        fn tag(&mut self) -> Result<Tag<'a>> {
            loop {
                let start = self.text[self.at..]
                    .find('<')
                    .map(|offset| self.at + offset)
                    .context("the document ends before its plist does")?;
                let rest = &self.text[start..];
                if rest.starts_with("<!--") {
                    let end = rest.find("-->").context("a comment is never closed")?;
                    self.at = start + end + 3;
                    continue;
                }
                if rest.starts_with("<?") || rest.starts_with("<!") {
                    let end = rest.find('>').context("a declaration is never closed")?;
                    self.at = start + end + 1;
                    continue;
                }
                let end = rest.find('>').context("a tag is never closed")?;
                let inner = rest[1..end].trim();
                self.at = start + end + 1;
                let name = |raw: &'a str| match raw.split_once(char::is_whitespace) {
                    Some((name, _attributes)) => name,
                    None => raw,
                };
                return Ok(if let Some(closing) = inner.strip_prefix('/') {
                    Tag::Close(closing.trim())
                } else if let Some(empty) = inner.strip_suffix('/') {
                    Tag::Empty(name(empty.trim()))
                } else {
                    Tag::Open(name(inner))
                });
            }
        }

        /// The text of an element just opened, up to its closing tag.
        fn text_until_close(&mut self, name: &str) -> Result<String> {
            let close = format!("</{name}>");
            let end = self.text[self.at..]
                .find(&close)
                .with_context(|| format!("a <{name}> is never closed"))?;
            let raw = &self.text[self.at..self.at + end];
            self.at += end + close.len();
            unescape(raw)
        }

        /// Skip the value whose tag was just read.
        fn skip(&mut self, tag: Tag<'a>) -> Result<()> {
            let name = match tag {
                Tag::Open(name) => name,
                Tag::Empty(_) => return Ok(()),
                Tag::Close(_) => bail!("a closing tag stands where a value belongs"),
            };
            match name {
                "array" | "dict" => loop {
                    match self.tag()? {
                        Tag::Close(closed) if closed == name => return Ok(()),
                        Tag::Close(other) => bail!("</{other}> closes a <{name}>"),
                        inner => self.skip(inner)?,
                    }
                },
                _ => self.text_until_close(name).map(drop),
            }
        }
    }

    /// Text with the five XML entities and numeric references resolved.
    fn unescape(raw: &str) -> Result<String> {
        let mut out = String::with_capacity(raw.len());
        let mut rest = raw;
        while let Some(amp) = rest.find('&') {
            out.push_str(&rest[..amp]);
            let after = &rest[amp + 1..];
            let semi = after.find(';').context("an entity has no closing ;")?;
            let entity = &after[..semi];
            let character = match entity {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                _ => {
                    let code = if let Some(hex) = entity.strip_prefix("#x") {
                        u32::from_str_radix(hex, 16)
                    } else if let Some(decimal) = entity.strip_prefix('#') {
                        decimal.parse()
                    } else {
                        bail!("&{entity}; is not an entity a plist may hold")
                    }
                    .with_context(|| format!("&{entity}; is not a character reference"))?;
                    char::from_u32(code)
                        .with_context(|| format!("&{entity}; names no character"))?
                }
            };
            out.push(character);
            rest = &after[semi + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    pub(super) fn program_arguments(text: &str) -> Result<Vec<String>> {
        let mut cursor = Cursor { text, at: 0 };
        match cursor.tag()? {
            Tag::Open("plist") => {}
            _ => bail!("the document is not a <plist>"),
        }
        match cursor.tag()? {
            Tag::Open("dict") => {}
            _ => bail!("the plist's top-level value is not a <dict>"),
        }
        loop {
            match cursor.tag()? {
                Tag::Close("dict") => bail!("the top-level dict has no ProgramArguments key"),
                Tag::Open("key") => {}
                _ => bail!("the top-level dict holds a value where a <key> belongs"),
            }
            let key = cursor.text_until_close("key")?;
            let value = cursor.tag()?;
            if key != "ProgramArguments" {
                cursor.skip(value)?;
                continue;
            }
            match value {
                Tag::Open("array") => {}
                _ => bail!("ProgramArguments is not an <array>"),
            }
            let mut arguments = Vec::new();
            loop {
                match cursor.tag()? {
                    Tag::Close("array") => return Ok(arguments),
                    Tag::Open("string") => arguments.push(cursor.text_until_close("string")?),
                    Tag::Empty("string") => arguments.push(String::new()),
                    _ => bail!("ProgramArguments holds a value that is not a <string>"),
                }
            }
        }
    }
}

mod binary {
    use anyhow::{bail, Context, Result};

    struct Plist<'a> {
        bytes: &'a [u8],
        offsets: Vec<usize>,
        reference_size: usize,
    }

    fn be(bytes: &[u8]) -> u64 {
        bytes
            .iter()
            .fold(0, |value, byte| (value << 8) | u64::from(*byte))
    }

    impl<'a> Plist<'a> {
        fn parse(bytes: &'a [u8]) -> Result<(Self, usize)> {
            let trailer = bytes
                .len()
                .checked_sub(32)
                .and_then(|start| bytes.get(start..))
                .context("the binary plist is shorter than its trailer")?;
            let offset_size = usize::from(trailer[6]);
            let reference_size = usize::from(trailer[7]);
            let count = usize::try_from(be(&trailer[8..16])).context("object count")?;
            let top = usize::try_from(be(&trailer[16..24])).context("top object")?;
            let table = usize::try_from(be(&trailer[24..32])).context("offset table")?;
            if !(1..=8).contains(&offset_size) || !(1..=8).contains(&reference_size) {
                bail!("the binary plist's trailer names sizes it cannot have");
            }
            let mut offsets = Vec::with_capacity(count);
            for index in 0..count {
                let start = table + index * offset_size;
                let raw = bytes
                    .get(start..start + offset_size)
                    .context("the binary plist's offset table runs past its end")?;
                offsets.push(usize::try_from(be(raw)).context("object offset")?);
            }
            Ok((
                Self {
                    bytes,
                    offsets,
                    reference_size,
                },
                top,
            ))
        }

        fn byte(&self, at: usize) -> Result<u8> {
            self.bytes
                .get(at)
                .copied()
                .context("an object runs past the end of the binary plist")
        }

        fn slice(&self, at: usize, length: usize) -> Result<&'a [u8]> {
            self.bytes
                .get(
                    at..at
                        .checked_add(length)
                        .context("an object's length overflows")?,
                )
                .context("an object runs past the end of the binary plist")
        }

        /// An object's marker, its count and where its body starts.
        fn head(&self, object: usize) -> Result<(u8, usize, usize)> {
            let at = *self
                .offsets
                .get(object)
                .context("a reference names no object")?;
            let marker = self.byte(at)?;
            let low = usize::from(marker & 0x0f);
            if low != 0x0f || marker >> 4 == 0 || marker >> 4 == 1 {
                return Ok((marker >> 4, low, at + 1));
            }
            let size = self.byte(at + 1)?;
            if size >> 4 != 1 {
                bail!("an object's length is not stated as an integer");
            }
            let width = 1usize << (size & 0x0f);
            let count = usize::try_from(be(self.slice(at + 2, width)?)).context("object length")?;
            Ok((marker >> 4, count, at + 2 + width))
        }

        fn string(&self, object: usize) -> Result<String> {
            match self.head(object)? {
                (0x5, count, body) => {
                    let raw = self.slice(body, count)?;
                    Ok(String::from_utf8(raw.to_vec()).context("an ASCII string is not text")?)
                }
                (0x6, count, body) => {
                    let raw = self.slice(body, count * 2)?;
                    let units: Vec<u16> = raw
                        .chunks_exact(2)
                        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                        .collect();
                    String::from_utf16(&units).context("a UTF-16 string is not text")
                }
                _ => bail!("a value that must be a string is another kind"),
            }
        }

        fn references(&self, body: usize, count: usize) -> Result<Vec<usize>> {
            (0..count)
                .map(|index| {
                    let raw =
                        self.slice(body + index * self.reference_size, self.reference_size)?;
                    usize::try_from(be(raw)).context("object reference")
                })
                .collect()
        }
    }

    pub(super) fn program_arguments(bytes: &[u8]) -> Result<Vec<String>> {
        let (plist, top) = Plist::parse(bytes)?;
        let (kind, count, body) = plist.head(top)?;
        if kind != 0xd {
            bail!("the plist's top-level value is not a dict");
        }
        let keys = plist.references(body, count)?;
        let values = plist.references(body + count * plist.reference_size, count)?;
        for (key, value) in keys.into_iter().zip(values) {
            if plist.string(key)? != "ProgramArguments" {
                continue;
            }
            let (kind, count, body) = plist.head(value)?;
            if kind != 0xa {
                bail!("ProgramArguments is not an array");
            }
            return plist
                .references(body, count)?
                .into_iter()
                .map(|element| plist.string(element))
                .collect();
        }
        bail!("the top-level dict has no ProgramArguments key")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_program_arguments_from_xml() {
        let text = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.example</string>
  <!-- a comment -->
  <key>EnvironmentVariables</key><dict><key>A</key><string>b</string></dict>
  <key>KeepAlive</key><true/>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/skarbiec</string>
    <string>sync-daemon</string>
    <string>--consumer</string>
    <string>a&amp;b &#x41;&#66;</string>
    <string/>
  </array>
</dict>
</plist>"#;
        assert_eq!(
            super::xml::program_arguments(text).unwrap(),
            [
                "/usr/local/bin/skarbiec",
                "sync-daemon",
                "--consumer",
                "a&b AB",
                ""
            ]
        );
        assert!(super::xml::program_arguments(
            "<plist><dict><key>Label</key><string>x</string></dict></plist>"
        )
        .is_err());
        assert!(super::xml::program_arguments(
            "<plist><dict><key>ProgramArguments</key><string>x</string></dict></plist>"
        )
        .is_err());
    }

    #[test]
    fn reads_program_arguments_from_binary() {
        // {"Label": "x", "ProgramArguments": ["/bin/a", "b"]}, as plutil
        // writes it: objects 0 dict, 1-2 keys, 3 "x", 4 array, 5-6 strings.
        let mut bytes = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        let mut push = |bytes: &mut Vec<u8>, object: &[u8]| {
            offsets.push(u8::try_from(bytes.len()).unwrap());
            bytes.extend_from_slice(object);
        };
        push(&mut bytes, &[0xd2, 1, 2, 3, 4]);
        push(&mut bytes, b"\x55Label");
        push(&mut bytes, b"\x5f\x10\x10ProgramArguments");
        push(&mut bytes, b"\x51x");
        push(&mut bytes, &[0xa2, 5, 6]);
        push(&mut bytes, b"\x56/bin/a");
        push(&mut bytes, &[0x61, 0, b'b']);
        let table = bytes.len();
        bytes.extend_from_slice(&offsets);
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 1]);
        bytes.extend_from_slice(&7u64.to_be_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&(table as u64).to_be_bytes());
        assert_eq!(
            super::binary::program_arguments(&bytes).unwrap(),
            ["/bin/a", "b"]
        );
        assert!(super::binary::program_arguments(&bytes[..20]).is_err());
    }
}
