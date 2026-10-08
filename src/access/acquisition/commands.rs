// The acquisition verbs an operator or a workload runs, and the exact
// refusals each of them answers with.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{consume, issue};
use crate::cli::args::OrUsage;

const REQUEST_USAGE: &str = "usage: acquisition request <consumer> <item> <field> --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX";
const READ_USAGE: &str =
    "usage: acquisition read <consumer> <item> <field> --token-file <path>";

/// `acquisition request|read` is a group: the object is the command and the
/// verb its first positional. The hyphenated spellings (`acquisition-request`,
/// `acquisition-read`) are still answered for workloads already written
/// against them; they go once those workloads run the group.
pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command == "acquisition" {
        return group(flags, positionals).map(Some);
    }
    let spelled;
    let command = match command.strip_prefix("acquisition-") {
        Some(verb) => {
            spelled = format!("acquisition {verb}");
            spelled.as_str()
        }
        None => command,
    };
    leaf(command, flags, positionals)
}

fn group(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let Some((verb, positionals)) = positionals.split_first() else {
        return Err(crate::cli::args::Usage(
            "acquisition needs a subcommand; `skarbiec acquisition help` lists them".to_string(),
        )
        .into());
    };
    if verb == "help" {
        return Ok(json!({
            "commands": [REQUEST_USAGE.trim_start_matches("usage: "), READ_USAGE.trim_start_matches("usage: ")],
            "usage": "acquisition request verifies a workload's signed proof and issues a short-lived one-use token for one field; acquisition read consumes that token, read from an owner-only file, and returns only its bound field.",
        }));
    }
    leaf(&format!("acquisition {verb}"), flags, positionals)?.ok_or_else(|| {
        crate::cli::args::Usage(format!(
            "unknown acquisition command: {verb}; `skarbiec acquisition help` lists them"
        ))
        .into()
    })
}

fn leaf(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "acquisition request" => {
            let consumer = positionals.first().or_usage(REQUEST_USAGE)?;
            let item = positionals.get(1).or_usage(REQUEST_USAGE)?;
            let field = positionals.get(2).or_usage(REQUEST_USAGE)?;
            let workload_id = flags
                .get("workload-id")
                .or_usage("--workload-id required")?;
            let timestamp = flags
                .get("workload-timestamp")
                .or_usage("--workload-timestamp required")?
                .parse()
                .or_usage("--workload-timestamp must be an epoch integer")?;
            let nonce = flags
                .get("workload-nonce")
                .or_usage("--workload-nonce required")?;
            let signature = flags
                .get("workload-signature")
                .or_usage("--workload-signature required")?;
            let Some(issued) = issue(
                consumer,
                item,
                field,
                workload_id,
                timestamp,
                nonce,
                signature,
            )?
            else {
                // A refusal is the command's failure, not a successful answer:
                // a caller reading the exit status must not see 0 here. The
                // proof's failed check is deliberately not named.
                anyhow::bail!(
                    "acquisition request: unauthorized: {consumer} has no acquire grant for {item}#{field} that this workload proof satisfies"
                );
            };
            crate::runtime::audit::append_sync(
                "acquisition-issued",
                &json!({
                    "consumer": consumer,
                    "item": item,
                    "field": field,
                    "workload_id": workload_id,
                    "expires_at": issued.expires_at,
                }),
            )?;
            Ok(Some(json!({
                "ok": true,
                "consumer": consumer,
                "item": item,
                "field": field,
                "expires_at": issued.expires_at,
                "token": issued.token,
            })))
        }
        "acquisition read" => {
            let consumer = positionals.first().or_usage(READ_USAGE)?;
            let item = positionals.get(1).or_usage(READ_USAGE)?;
            let field = positionals.get(2).or_usage(READ_USAGE)?;
            let presented = &crate::credential::bearer_from_file(flags, "acquisition read")?;
            let Some(acquired) = consume(consumer, presented, item, field)? else {
                anyhow::bail!(
                    "acquisition read: unauthorized: the token is unknown, expired, already spent, or not bound to {consumer} {item}#{field}"
                );
            };
            crate::runtime::audit::append_sync(
                "acquisition-consumed",
                &json!({"consumer": consumer, "item": item, "field": field}),
            )?;
            let mut answer = json!({
                "ok": true,
                "consumer": consumer,
                "item": item,
                "field": field,
                "value": acquired.value,
            });
            if let Some(provider) = acquired.provider {
                answer["provider"] = json!(provider);
            }
            Ok(Some(answer))
        }
        _ => Ok(None),
    }
}
