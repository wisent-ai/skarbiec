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
    /// The status a usage error exits with, as clap's own usage errors do:
    /// https://docs.rs/clap/latest/clap/error/struct.Error.html#method.exit
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
            } else if let Some(value) = iter.next_if(|next| !next.starts_with("--")) {
                flags.insert(name.to_string(), value.clone());
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
    matches!(flags.get(name).map(String::as_str), Some("true"))
}

/// The arguments after `<noun> <verb>` when the invocation is that pair, so
/// a module answering one verb of a noun several modules share says None to
/// every other one and the next module is asked.
pub(crate) fn verb<'a>(
    command: &str,
    positionals: &'a [String],
    noun: &str,
    verb: &str,
) -> Option<&'a [String]> {
    match positionals.split_first() {
        Some((first, rest)) if command == noun && first == verb => Some(rest),
        _ => None,
    }
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
    TEXT.get_or_init(|| asked);
}

/// Print one result: JSON for machines by default, the same document as
/// indented `key: value` lines for people with `--text`.
pub(crate) fn emit(value: &Value) -> Result<()> {
    if matches!(TEXT.get(), Some(true)) {
        let mut text = String::new();
        render(value, "", &mut text);
        print!("{text}");
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

/// What a value is to the text form: one line, or labelled entries nested
/// below the line that names it. Every value is exactly one of these, so the
/// renderer has no case it cannot print.
enum Shape<'a> {
    Line(String),
    Entries(Vec<(String, &'a Value)>),
}

fn shape(value: &Value) -> Shape<'_> {
    match value {
        Value::Null => Shape::Line("none".to_string()),
        Value::String(text) => Shape::Line(text.clone()),
        Value::Bool(_) | Value::Number(_) => Shape::Line(value.to_string()),
        Value::Array(items) if items.is_empty() => Shape::Line("(none)".to_string()),
        Value::Object(fields) if fields.is_empty() => Shape::Line("(none)".to_string()),
        Value::Object(fields) => Shape::Entries(
            fields
                .iter()
                .map(|(key, field)| (format!("{key}:"), field))
                .collect(),
        ),
        Value::Array(items) => {
            Shape::Entries(items.iter().map(|item| ("-".to_string(), item)).collect())
        }
    }
}

/// `value` as lines under the indentation `pad`; each nesting level adds two
/// spaces to it.
fn render(value: &Value, pad: &str, out: &mut String) {
    match shape(value) {
        Shape::Line(text) => out.push_str(&format!("{pad}{text}\n")),
        Shape::Entries(entries) => {
            let nested = format!("{pad}  ");
            for (label, field) in entries {
                match shape(field) {
                    Shape::Line(text) => out.push_str(&format!("{pad}{label} {text}\n")),
                    Shape::Entries(_) => {
                        out.push_str(&format!("{pad}{label}\n"));
                        render(field, &nested, out);
                    }
                }
            }
        }
    }
}
