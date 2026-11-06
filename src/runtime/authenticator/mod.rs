// `skarbiec totp uri <id>`: the otpauth:// address of one item's
// authenticator seed, in the Key URI Format authenticator apps scan from a QR
// code — for moving a second factor to a phone, or keeping a second device
// enrolled, without asking the site for a new seed. It reveals the seed, as
// `get --field totp_secret` does, so it is an owner read: it opens the item
// with the owner's key and its use is journalled with the item, never the
// value. The address carries the parameters this vault computes codes with,
// so the phone answers the same codes the vault does.
// Key URI Format: https://github.com/google/google-authenticator/wiki/Key-Uri-Format

use anyhow::Result;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::Usage;
use crate::core::items::{display_name, item_domains};
use crate::core::totp::{DIGITS, PERIOD_SECONDS};
use crate::core::{vault::Vault, vault_path};

/// The HMAC this vault computes codes with, as the Key URI Format names it.
const ALGORITHM: &str = "SHA1";

pub fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    let Some(rest) = crate::cli::args::verb(command, positionals, "totp", "uri") else {
        return Ok(None);
    };
    let [id] = rest else {
        return Err(Usage("usage: totp uri <item-id>".to_string()).into());
    };
    uri(id).map(Some)
}

fn text<'p>(payload: &'p Value, field: &str) -> Option<&'p str> {
    payload
        .get("fields")
        .and_then(|fields| fields.get(field))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn uri(id: &str) -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    let payload = vault.get_item(id)?;
    let Some(seed) = text(&payload, "totp_secret") else {
        anyhow::bail!(
            "{id} keeps no authenticator seed, so there is no address to move; \
             `skarbiec totp set {id}` stores one from the site's QR code"
        );
    };
    let context = payload.get("context");
    // The issuer an app shows: the item's name, else the first site it signs
    // in to, else its id — each is the owner's own word for the account.
    let issuer = match context.and_then(display_name) {
        Some(name) => name.to_string(),
        None => match context
            .map(item_domains)
            .and_then(|domains| domains.into_iter().next())
        {
            Some(site) => site,
            None => id.to_string(),
        },
    };
    let account = match text(&payload, "username") {
        Some(username) => username.to_string(),
        None => id.to_string(),
    };
    let encode = |part: &str| utf8_percent_encode(part, NON_ALPHANUMERIC).to_string();
    let address = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={ALGORITHM}&digits={DIGITS}&period={PERIOD_SECONDS}",
        encode(&issuer),
        encode(&account),
        encode(&seed.replace(' ', "").to_uppercase()),
        encode(&issuer),
    );
    crate::runtime::audit::append("totp-uri-read", &json!({"item": id}))?;
    Ok(json!({"ok": true, "item": id, "issuer": issuer, "account": account, "uri": address}))
}
