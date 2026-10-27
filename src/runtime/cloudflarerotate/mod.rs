// The cloudflare adapter of `skarbiec rotate <id> --with cloudflare [--account <account id>]`: roll a
// Cloudflare API token a token item keeps, through Cloudflare's own API. The
// stored token asks /tokens/verify which token it is, then rolls its own
// value (PUT /tokens/<token id>/value), which ends the old value and answers
// a new one with the same permissions. The new value is stored as the item's
// next revision — or, when the vault cannot take it, in an owner-only file
// named in the refusal, since Cloudflare has ended the old one — and verified
// again to prove it. User tokens live under /user, account-owned tokens under
// /accounts/<account id>, which --account names. The token reaches curl only
// as a header on its standard input.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::Usage;
use crate::core::{vault::Vault, vault_path};

pub(crate) const USAGE: &str = "usage: rotate <id> --with cloudflare [--account <account id>]";
const FIELD: &str = "token";
const API: &str = "https://api.cloudflare.com/client/v4";

/// Roll `id`'s Cloudflare token, as `rotate <id> --with cloudflare` asks.
pub(crate) fn rotate_item(flags: &HashMap<String, String>, id: &str) -> Result<Value> {
    let owner = match flags.get("account") {
        Some(account) if !account.is_empty() && account.chars().all(|character| character.is_ascii_alphanumeric()) => format!("accounts/{account}"),
        Some(account) => return Err(Usage(format!("--account {account} is not a Cloudflare account id. {USAGE}")).into()),
        None => "user".to_string(),
    };
    rotate(id, &owner)
}

/// Call Cloudflare's API signed in with `token` and answer its `result`,
/// naming Cloudflare's own errors when it does not report success.
fn cloudflare(method: &str, path: &str, token: &str, body: Option<&Value>) -> Result<Value> {
    let url = format!("{API}/{path}");
    let header = format!("Authorization: Bearer {token}");
    let answer = crate::runtime::apicall::call(&crate::runtime::apicall::Call { method, url: &url, header: &header, form: &[], json: body })
        .with_context(|| format!("Cloudflare refused {method} {path}"))?;
    if answer["success"] != json!(true) {
        bail!("Cloudflare answered {method} {path} without success: {}", answer["errors"]);
    }
    Ok(answer["result"].clone())
}

fn rotate(id: &str, owner: &str) -> Result<Value> {
    let old = {
        let vault = Vault::open(vault_path())?;
        crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "rotate")?;
        let payload = vault.get_item(id)?;
        if payload["kind"] != json!("token") {
            bail!("{id} is a {} item; rotate --with cloudflare rolls the token a token item keeps", payload["kind"]);
        }
        payload["fields"][FIELD].as_str().filter(|token| !token.is_empty()).with_context(|| format!("{id} holds no {FIELD}"))?.to_string()
    };
    let verified = cloudflare("GET", &format!("{owner}/tokens/verify"), &old, None)?;
    let token_id = verified["id"].as_str().context("Cloudflare verified the token but named no token id")?.to_string();
    let rolled = cloudflare("PUT", &format!("{owner}/tokens/{token_id}/value"), &old, Some(&json!({})))?;
    let new = rolled.as_str().context("Cloudflare rolled the token but answered no new value")?.to_string();
    let revision = crate::runtime::revise::issued(id, FIELD, &new, "Cloudflare")?;
    let proven = cloudflare("GET", &format!("{owner}/tokens/verify"), &new, None)
        .with_context(|| format!("{id} holds Cloudflare's new value at revision {revision}, but Cloudflare did not verify it"))?;
    // A token Cloudflare ends on a day has that day recorded as the item's
    // expiry, so review warns before it runs out; one that cannot be recorded
    // is said after the roll stands.
    let expiry = match proven["expires_on"].as_str() {
        Some(on) => match crate::runtime::expiry::set(id, on) {
            Ok(set) => set,
            Err(error) => json!({"recorded": false, "error": format!("{error:#}")}),
        },
        None => Value::Null,
    };
    crate::runtime::audit::append(
        "cloudflare-token-rotated",
        &json!({"item": id, "token_id": token_id, "owner": owner, "revision": revision}),
    )?;
    Ok(json!({"ok": true, "item": id, "token_id": token_id, "status": proven["status"], "expires_on": proven["expires_on"], "expiry": expiry, "revision": revision}))
}
