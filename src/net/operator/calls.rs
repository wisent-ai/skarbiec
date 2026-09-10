// Reading one operator request body and calling the backend it names. The
// bodies carry JSON; the backends take the flags and positionals a command
// line would have carried.

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashMap;

use crate::core;

/// One dispatcher's answer, with the no-match case named: a route here always
/// stands for a real command, so `None` is a bug in this table, not an answer.
pub(super) fn answered(result: Result<Option<Value>>) -> Result<Value> {
    result?.context("the backend produced no answer for an operator route")
}

pub(super) fn access(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    answered(crate::access::dispatch(command, flags, positionals))
}

/// One `grant` leaf: the subcommand this route stands for, in front of the
/// positionals its body named. The group takes the leaf as its first
/// positional, so a console and the command line reach the same dispatcher
/// with the same argument list.
pub(super) fn grant(
    leaf: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    let mut argv = vec![leaf.to_string()];
    argv.extend_from_slice(positionals);
    access("grant", flags, &argv)
}

pub(super) fn runtime(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    answered(crate::runtime::dispatch(command, flags, positionals))
}

pub(super) fn net(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    answered(crate::net::dispatch(command, flags, positionals))
}

pub(super) fn bonds(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    answered(crate::bonds::dispatch(command, flags, positionals))
}

pub(super) fn inbox(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    answered(crate::core::inbox::dispatch(command, flags, positionals))
}

pub(super) fn credential(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    answered(crate::credential::dispatch(
        "credential",
        flags,
        positionals,
        &core::vault_path(),
    ))
}

/// A required body member, named when absent so the console learns which of
/// its fields the route asked for.
pub(super) fn text(parsed: &Value, key: &str) -> Result<String> {
    optional(parsed, key).with_context(|| format!("{key} required"))
}

pub(super) fn optional(parsed: &Value, key: &str) -> Option<String> {
    parsed
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// The flags one dispatcher call gets, built from body members this route
/// named: a console can narrow a question, never smuggle a flag past the
/// route table. Strings pass through, numbers render, `true` sets a bare
/// flag — the shapes the flag parser already understands.
pub(super) fn flags(parsed: &Value, keys: &[&str]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for key in keys {
        match parsed.get(*key) {
            Some(Value::String(value)) if !value.is_empty() => {
                out.insert((*key).to_string(), value.clone());
            }
            Some(Value::Bool(true)) => {
                out.insert((*key).to_string(), "true".to_string());
            }
            Some(value @ Value::Number(_)) => {
                out.insert((*key).to_string(), value.to_string());
            }
            _ => {}
        }
    }
    out
}

pub(super) fn positionals(parsed: &Value, keys: &[&str]) -> Result<Vec<String>> {
    keys.iter().map(|key| text(parsed, key)).collect()
}
