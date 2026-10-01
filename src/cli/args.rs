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

pub(crate) fn emit(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
