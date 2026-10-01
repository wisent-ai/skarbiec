// What a command line is: key=value flags, bare `--flag` switches, and the
// positionals left over. One parser so every command reads its arguments the
// same way, and one type for an invocation that is itself wrong.

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::process::ExitCode;

/// The invocation is wrong -- a missing argument or flag, an unknown command
/// -- as opposed to a refusal of a well-formed request. It is a type rather
/// than a phrase so `main` can tell the two apart without reading messages:
/// a usage error exits 2, every other failure 1.
#[derive(Debug)]
pub(crate) struct Usage(pub(crate) String);

impl fmt::Display for Usage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Usage {}

/// `context` for a value the invocation had to supply: absent (`Option`) or
/// present but malformed (`Result`, e.g. a `parse` of a flag's value).
pub(crate) trait OrUsage<T> {
    fn or_usage(self, text: &str) -> Result<T>;
}

impl<T> OrUsage<T> for Option<T> {
    fn or_usage(self, text: &str) -> Result<T> {
        self.ok_or_else(|| Usage(text.to_string()).into())
    }
}

impl<T, E: fmt::Display> OrUsage<T> for std::result::Result<T, E> {
    fn or_usage(self, text: &str) -> Result<T> {
        self.map_err(|error| Usage(format!("{text}: {error}")).into())
    }
}

/// The documented exit status: 2 for a usage error, 1 for any other failure.
pub(crate) fn exit_code(error: &anyhow::Error) -> ExitCode {
    const USAGE_STATUS: u8 = 2;
    if error.chain().any(|cause| cause.is::<Usage>()) {
        ExitCode::from(USAGE_STATUS)
    } else {
        ExitCode::FAILURE
    }
}

// key=value or bare --flag (present -> "true"); everything else is positional.
pub(crate) fn parse_args(rest: &[String]) -> (HashMap<String, String>, Vec<String>) {
    let mut flags = HashMap::new();
    let mut positionals = Vec::new();
    let mut iter = rest.iter().peekable();
    while let Some(arg) = iter.next() {
        if let Some(name) = arg.strip_prefix("--") {
            if let Some((k, v)) = name.split_once('=') {
                flags.insert(k.to_string(), v.to_string());
            } else if iter.peek().map(|n| !n.starts_with("--")).unwrap_or(false) {
                flags.insert(name.to_string(), iter.next().cloned().unwrap_or_default());
            } else {
                flags.insert(name.to_string(), "true".to_string());
            }
        } else {
            positionals.push(arg.clone());
        }
    }
    (flags, positionals)
}

pub(crate) fn flag_set(flags: &HashMap<String, String>, name: &str) -> bool {
    flags.get(name).map(|v| v == "true").unwrap_or(false)
}

/// Whether this invocation asked for text: `main` takes `--text` out of the
/// arguments before any command parses them, so no command has to know it.
/// A `OnceLock`, because the answer is runtime input, not a known initializer.
static TEXT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Remove `--text` and `--json` from the command line and remember whether
/// text was asked for. `--json` names the default form; left in, the flag
/// parser would take the next word (`skarbiec get --json ITEM`) as its value
/// and the command would run without its item.
pub(crate) fn take_text_switch(rest: &mut Vec<String>) {
    let asked = rest.iter().any(|word| word == "--text");
    rest.retain(|word| word != "--text" && word != "--json");
    let _ = TEXT.set(asked);
}

/// Print one result: JSON for machines by default, the same document as
/// indented `key: value` lines for people with `--text`.
pub(crate) fn emit(value: &Value) -> Result<()> {
    if TEXT.get().copied().unwrap_or(false) {
        let mut text = String::new();
        render(value, 0, &mut text);
        print!("{text}");
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("none".to_string()),
        Value::String(text) => Some(text.clone()),
        Value::Bool(_) | Value::Number(_) => Some(value.to_string()),
        Value::Array(items) if items.is_empty() => Some("(none)".to_string()),
        Value::Object(fields) if fields.is_empty() => Some("(none)".to_string()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn render(value: &Value, depth: usize, out: &mut String) {
    let pad = "  ".repeat(depth);
    match value {
        Value::Object(fields) if !fields.is_empty() => {
            for (key, field) in fields {
                match scalar(field) {
                    Some(text) => out.push_str(&format!("{pad}{key}: {text}\n")),
                    None => {
                        out.push_str(&format!("{pad}{key}:\n"));
                        render(field, depth + 1, out);
                    }
                }
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for item in items {
                match scalar(item) {
                    Some(text) => out.push_str(&format!("{pad}- {text}\n")),
                    None => {
                        out.push_str(&format!("{pad}-\n"));
                        render(item, depth + 1, out);
                    }
                }
            }
        }
        other => out.push_str(&format!("{pad}{}\n", scalar(other).unwrap_or_default())),
    }
}
