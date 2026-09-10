// The acquisition verbs an operator or a workload runs, and the exact
// refusals each of them answers with.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{consume, issue};

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "acquisition-request" => {
            let consumer = positionals.first().context(
                "usage: acquisition-request <consumer> <item> <field> --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX",
            )?;
            let item = positionals.get("1".parse::<usize>()?).context(
                "usage: acquisition-request <consumer> <item> <field> --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX",
            )?;
            let field = positionals.get("2".parse::<usize>()?).context(
                "usage: acquisition-request <consumer> <item> <field> --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX",
            )?;
            let workload_id = flags.get("workload-id").context("--workload-id required")?;
            let timestamp = flags
                .get("workload-timestamp")
                .context("--workload-timestamp required")?
                .parse()
                .context("--workload-timestamp must be an epoch integer")?;
            let nonce = flags
                .get("workload-nonce")
                .context("--workload-nonce required")?;
            let signature = flags
                .get("workload-signature")
                .context("--workload-signature required")?;
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
                return Ok(Some(json!({"ok": false, "error": "unauthorized"})));
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
                .context("usage: acquisition-read <consumer> <item> <field> --token ACQUISITION")?;
            let item = positionals
                .get("1".parse::<usize>()?)
                .context("usage: acquisition-read <consumer> <item> <field> --token ACQUISITION")?;
            let field = positionals
                .get("2".parse::<usize>()?)
                .context("usage: acquisition-read <consumer> <item> <field> --token ACQUISITION")?;
            let presented = flags.get("token").context("--token required")?;
            let Some(acquired) = consume(consumer, presented, item, field)? else {
                return Ok(Some(json!({"ok": false, "error": "unauthorized"})));
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
