// Invite: register one exact, workload-bound acquisition capability and return
// its non-secret redemption contract. The value is revealed only through the
// signed acquisition-request / single-use acquisition-read exchange.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "invite" => {
            let item = positionals.first().context(
                "usage: invite <item> --field <field> --for <consumer> --workload-public-key-file PATH",
            )?;
            let field = flags.get("field").context("--field <field> required")?;
            let consumer = flags.get("for").context("--for <consumer> required")?;
            let workload_key = flags
                .get("workload-public-key-file")
                .context("--workload-public-key-file required")?;
            let mint_flags = HashMap::from([
                (
                    "capabilities".to_string(),
                    format!("acquire:{item}#{field}"),
                ),
                (
                    "workload-public-key-file".to_string(),
                    workload_key.to_string(),
                ),
            ]);
            let minted = crate::access::tokens::dispatch(
                "token-mint",
                &mint_flags,
                std::slice::from_ref(consumer),
            )?
            .context("token-mint produced no result")?;
            crate::runtime::audit::append(
                "invite",
                &json!({"item": item, "field": field, "consumer": consumer}),
            )?;
            Ok(Some(json!({
                "item": item,
                "field": field,
                "consumer": consumer,
                "workload_bound": minted.get("workload_bound"),
                "expires_at": minted.get("expires_at"),
                "redeem": {
                    "how": format!(
                        "sign an acquisition proof, then run: skarbiec acquisition-request {consumer} {item} {field} --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX; consume its token once with acquisition-read"
                    ),
                },
            })))
        }
        _ => Ok(None),
    }
}
