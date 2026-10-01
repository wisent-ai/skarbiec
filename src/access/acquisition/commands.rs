// The acquisition verbs an operator or a workload runs, and the exact
// refusals each of them answers with.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{consume, issue};
use crate::cli::args::OrUsage;

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "acquisition-request" => {
            let consumer = positionals.first().or_usage(
                "usage: acquisition-request <consumer> <item> <field> --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX",
            )?;
            let item = positionals.get("1".parse::<usize>()?).or_usage(
                "usage: acquisition-request <consumer> <item> <field> --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX",
            )?;
            let field = positionals.get("2".parse::<usize>()?).or_usage(
                "usage: acquisition-request <consumer> <item> <field> --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX",
            )?;
            let workload_id = flags.get("workload-id").or_usage("--workload-id required")?;
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
                    "acquisition-request: unauthorized: {consumer} has no acquire grant for {item}#{field} that this workload proof satisfies"
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
        "acquisition-read" => {
            let consumer = positionals
                .first()
                .or_usage("usage: acquisition-read <consumer> <item> <field> --token-file <path>")?;
            let item = positionals
                .get("1".parse::<usize>()?)
                .or_usage("usage: acquisition-read <consumer> <item> <field> --token-file <path>")?;
            let field = positionals
                .get("2".parse::<usize>()?)
                .or_usage("usage: acquisition-read <consumer> <item> <field> --token-file <path>")?;
            let presented = &crate::credential::bearer_from_file(flags, "acquisition-read")?;
            let Some(acquired) = consume(consumer, presented, item, field)? else {
                anyhow::bail!(
                    "acquisition-read: unauthorized: the token is unknown, expired, already spent, or not bound to {consumer} {item}#{field}"
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
