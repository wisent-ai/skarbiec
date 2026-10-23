// Reading one operator request body and calling the backend it names. The
// bodies carry JSON; the backends take the flags and positionals a command
// line would have carried.

use anyhow::{bail, Context, Result};
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

/// One `rotation` leaf, reached through the same dispatcher the command line
/// uses, with the leaf in front of the positionals its body named.
pub(super) fn rotation(
    leaf: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    let mut arguments = vec![leaf.to_string()];
    arguments.extend_from_slice(positionals);
    answered(crate::credential::dispatch(
        "rotation",
        flags,
        &arguments,
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

/// One `request` leaf: the access request register's list, approve and deny,
/// reached through the same dispatcher the command line uses.
pub(super) fn request(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    answered(crate::access::request::dispatch(
        command,
        flags,
        positionals,
    ))
}

/// One `/v1/operator/credential` operation, already checked against the list
/// routes.rs serves.
pub(super) fn credential_operation(operation: String, parsed: &Value) -> Result<Value> {
    match operation.as_str() {
        "status" | "acquire" | "rotate" | "resume" => {
            // Always this vault file: the console reports on and drives the
            // vault in view, never a canonical Skarbiec somewhere else.
            let mut call_flags = flags(parsed, &["provider", "consumer", "purpose", "account"]);
            call_flags.insert("local".to_string(), "true".to_string());
            credential(&call_flags, &[operation, text(parsed, "item")?])
        }
        "get" => {
            let call_flags = flags(parsed, &["field"]);
            crate::core::values::dispatch(
                "credential",
                &call_flags,
                &["get".to_string(), text(parsed, "item")?],
            )?
            .context("get operation failed")
        }
        "set" => {
            let item_id = text(parsed, "item")?;
            let call_flags = flags(parsed, &["type"]);
            // Collect all remaining fields from the parsed JSON (excluding known keys)
            let mut field_updates = Vec::new();
            if let Some(obj) = parsed.as_object() {
                for (key, value) in obj.iter() {
                    if !["operation", "item", "type", "vault"].contains(&key.as_str()) {
                        if let Some(s) = value.as_str() {
                            field_updates.push(format!("{}={}", key, s));
                        }
                    }
                }
            }
            let mut positionals = vec!["set".to_string(), item_id];
            positionals.extend(field_updates);
            crate::core::values::dispatch("credential", &call_flags, &positionals)?
                .context("set operation failed")
        }
        "set-json" => {
            let item_id = text(parsed, "item")?;
            let mut call_flags = flags(parsed, &["type", "tags", "recipients", "if-absent"]);
            // Pass the payload as a special flag to the dispatcher
            if let Some(payload) = parsed.get("payload") {
                call_flags.insert("__payload__".to_string(), payload.to_string());
            }
            let positionals = vec!["set-json".to_string(), item_id];
            crate::core::values::dispatch("credential", &call_flags, &positionals)?
                .context("set-json operation failed")
        }
        "totp" => {
            let call_flags = flags(parsed, &[]);
            let positionals = vec![text(parsed, "item")?];
            crate::runtime::totp::dispatch("totp", &call_flags, &positionals)?
                .context("totp operation failed")
        }
        _ => bail!("unknown credential operation: {}", operation),
    }
}
