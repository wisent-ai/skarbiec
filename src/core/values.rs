// Value operations on vault items: get and set.
//
// These are the same operations the command line offers, delegating to the
// same Vault API so the operator console and the local vault cannot drift.
// Writing goes through set alone: the payload arrives whole on standard
// input (or in the console's request body) and is validated as one canonical
// document, never rebuilt from key=value pairs under an assumed kind.

use crate::cli::args::OrUsage;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

/// The answer to one value operation, or none when `command` and its first
/// positional name no operation this module serves.
pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    let [subcommand, operands @ ..] = positionals else {
        return Ok(None);
    };
    match (command, subcommand.as_str()) {
        ("credential", "get") => {
            let id = operands
                .first()
                .or_usage("usage: credential get <id> [--field <field>]")?;
            let value = crate::cli::reads::get_value(flags, std::slice::from_ref(id))?;
            if flags.contains_key("field") {
                Ok(Some(json!({"value": value})))
            } else {
                // Return the full item as a JSON string wrapped in the value field
                let item_json = serde_json::to_string(&value)?;
                Ok(Some(json!({"value": item_json})))
            }
        }
        ("credential", "set") => {
            let id = operands
                .first()
                .or_usage("usage: credential set <id> [--type <canonical-kind>]")?;
            let encoded = flags.get("__payload__").context("set payload required")?;
            Ok(Some(crate::cli::items::set_json_value(flags, id, encoded)?))
        }
        _ => Ok(None),
    }
}
