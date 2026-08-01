// Invite: wrap an acquisition bootstrap grant into one JSON package the owner
// can hand to a consumer out of band. The package carries only the bootstrap
// token and redemption instructions — never the secret itself; the value is
// revealed only through the existing acquisition-request / acquisition-read
// exchange.

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
            let item = positionals
                .first()
                .context("usage: invite <item> --for <consumer>")?;
            let consumer = flags.get("for").context("--for <consumer> required")?;
            // The whole secret travels under the conventional field name.
            let field = "value";
            let mut mint_flags = HashMap::new();
            mint_flags.insert("acquisition-scopes".to_string(), format!("{item}#{field}"));
            let minted = crate::access::tokens::dispatch(
                "token-mint",
                &mint_flags,
                std::slice::from_ref(consumer),
            )?
            .context("token-mint produced no result")?;
            let bootstrap = minted
                .get("token")
                .and_then(Value::as_str)
                .context("mint produced no bootstrap token")?;
            crate::runtime::audit::append(
                "invite",
                &json!({"item": item, "field": field, "consumer": consumer}),
            )?;
            Ok(Some(json!({
                "item": item,
                "field": field,
                "consumer": consumer,
                "bootstrap_token": bootstrap,
                "redeem": {
                    "how": format!(
                        "skarbiec acquisition-request {consumer} {item} {field} --token <bootstrap> then acquisition-read {consumer} {item} {field} --token <issued>"
                    ),
                },
            })))
        }
        _ => Ok(None),
    }
}
