// `POST /v1/offers`: a consumer offers a new login — the browser extension
// right after a sign-up — and it waits, sealed to the owner's key, in the
// donation inbox until the owner accepts it with `donation accept`, exactly
// as a donated item does. The consumer needs one capability, `offer:logins`;
// it reads nothing, and the admission rule that guards donations refuses an
// offer under an id the owner or another writer already holds.

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::net::TcpStream;

use crate::access::grant;
use crate::core::{crypto, inbox, schema};
use crate::net::http;

/// The resource an `offer` capability names.
pub(crate) const OFFERED: &str = "logins";
const KIND: &str = "login";

fn text<'v>(body: &'v Value, key: &str) -> Option<&'v str> {
    body.get(key).and_then(Value::as_str).map(str::trim).filter(|text| !text.is_empty())
}

/// The item id an offer arrives under: the site and the username, lower
/// case, every character an id does not hold an underscore, so two offers of
/// one account meet under one id and the owner sees whose it is.
fn offered_id(site: &str, username: &str) -> String {
    format!("{site}-{username}")
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

pub(crate) fn handle_offer(stream: &mut TcpStream, headers: &HashMap<String, String>, body: &str) -> Result<()> {
    let bad = "HTTP/1.1 400 Bad Request";
    let Some(parsed) = http::request_json(stream, body)? else {
        return Ok(());
    };
    let (Some(site), Some(username), Some(password)) =
        (text(&parsed, "site"), text(&parsed, "username"), text(&parsed, "password"))
    else {
        return http::write_response(stream, bad, &json!({"error": "site, username and password are required"}));
    };
    if let Err(error) = crate::runtime::gitcred::checked_host(site) {
        return http::write_response(stream, bad, &json!({"error": format!("{error:#}")}));
    }
    let (consumer, bearer) = match http::presented_identity(headers) {
        Ok(identity) => identity,
        Err(reason) => return http::unidentified(stream, &reason),
    };
    let vault = http::load()?;
    if !grant::token_allows_vault_action(&vault, &consumer, &bearer, "offer", OFFERED)? {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": format!("offer:{OFFERED} grant required")}),
        );
    }
    let id = offered_id(site, username);
    let rule = inbox::admission(&vault, &id, &consumer);
    if !rule.admits() {
        crate::runtime::audit::append(
            "login-offer-refused",
            &json!({"item": id, "consumer": consumer, "status": rule.name()}),
        )?;
        return http::write_response(
            stream,
            "HTTP/1.1 200 OK",
            &json!({"ok": false, "status": rule.name(), "id": id}),
        );
    }
    let mut fields = Map::new();
    fields.insert("username".to_string(), json!(username));
    fields.insert("password".to_string(), json!(password));
    let mut context = Map::new();
    context.insert("domains".to_string(), json!([site.to_lowercase()]));
    let payload = schema::payload(KIND, fields, context)?;
    let owner = vault.owner_uid().to_string();
    let fingerprint = vault
        .recipient_fpr(&owner)
        .with_context(|| format!("the vault's owner {owner} has no registered key to seal the offer to"))?;
    let armor = crypto::encrypt_to(&[fingerprint], &serde_json::to_string(&payload)?)?;
    let donation_id = inbox::enqueue(&id, &consumer, &consumer, KIND, &armor)?;
    crate::runtime::audit::append(
        "login-offered",
        &json!({"donation": donation_id, "item": id, "consumer": consumer, "site": site}),
    )?;
    http::write_response(
        stream,
        "HTTP/1.1 200 OK",
        &json!({"ok": true, "status": "pending", "donation_id": donation_id, "id": id}),
    )
}
