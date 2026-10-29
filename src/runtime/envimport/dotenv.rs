// The variables a .env file sets, read the way the common loaders read one:
// NAME=value a line, an optional leading `export `, blank lines and lines
// starting with # skipped. A value in double quotes takes \n as a newline
// and a backslash before any other character as that character; one in
// single quotes is taken as written; an unquoted one ends before ` #`. A
// line that is none of these is refused with its number, never skipped, so
// no secret is left behind in the file unnoticed.

use anyhow::{bail, Result};

/// One variable the file sets, with the line that sets it.
pub(super) struct Variable {
    pub(super) line: usize,
    pub(super) name: String,
    pub(super) value: String,
}

pub(super) fn read(text: &str) -> Result<Vec<Variable>> {
    let mut variables: Vec<Variable> = Vec::new();
    let mut seen = Vec::new();
    for raw in text.lines() {
        seen.push(raw);
        let line = seen.len();
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let statement = match trimmed.strip_prefix("export ") {
            Some(exported) => exported.trim_start(),
            None => trimmed,
        };
        let Some((name, value)) = statement.split_once('=') else {
            bail!("line {line} is not NAME=value, a comment or blank");
        };
        let name = name.trim();
        if !crate::runtime::exec::is_variable(name) {
            bail!("line {line}: {name} is not a variable name; use letters, digits and underscores, not starting with a digit");
        }
        if let Some(earlier) = variables.iter().find(|variable| variable.name == name) {
            bail!(
                "line {line} sets {name} again, first set on line {}; keep one",
                earlier.line
            );
        }
        variables.push(Variable {
            line,
            name: name.to_string(),
            value: unquote(value.trim(), line)?,
        });
    }
    Ok(variables)
}

fn unquote(value: &str, line: usize) -> Result<String> {
    if let Some(inner) = value.strip_prefix('"') {
        let Some(inner) = inner.strip_suffix('"') else {
            bail!("line {line}: the double-quoted value does not end on its line; a value across lines is not read");
        };
        return Ok(unescape(inner));
    }
    if let Some(inner) = value.strip_prefix('\'') {
        let Some(inner) = inner.strip_suffix('\'') else {
            bail!("line {line}: the single-quoted value does not end on its line; a value across lines is not read");
        };
        return Ok(inner.to_string());
    }
    let kept = match value.split_once(" #") {
        Some((kept, _comment)) => kept.trim_end(),
        None => value,
    };
    Ok(kept.to_string())
}

fn unescape(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some(escaped) => out.push(escaped),
            None => out.push('\\'),
        }
    }
    out
}
