// The twilio adapter of `skarbiec rotate <id> --with twilio`: replace a Twilio account's auth token kept in
// an api-key item — api_user the Account SID, api_key the auth token —
// through Twilio's own secondary-token flow. Signed in with the current
// token, Twilio makes a secondary token; the vault stores it as the item's
// next revision; the secondary token signs in to the account, proving Twilio
// takes it; then it is promoted, which ends the old token. Before the
// promotion nothing has ended: a failure deletes the secondary token again
// and writes the old one back. Tokens reach curl only as a header on its
// standard input; the answer names the account, never a token.

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{vault::Vault, vault_path};
use crate::runtime::apicall::{call, Call};

pub(crate) const USAGE: &str = "usage: rotate <id> --with twilio";
const KIND: &str = "api-key";
const SID: &str = "api_user";
const TOKEN: &str = "api_key";
const ACCOUNTS: &str = "https://accounts.twilio.com/v1/AuthTokens";
const API: &str = "https://api.twilio.com/2010-04-01/Accounts";
/// What every Account SID starts with.
const SID_PREFIX: &str = "AC";

/// Replace `id`'s auth token, as `rotate <id> --with twilio` asks.
pub(crate) fn rotate_item(_flags: &HashMap<String, String>, id: &str) -> Result<Value> {
    rotate(id)
}

/// The Basic header Twilio signs in with: the Account SID and a token.
fn header(sid: &str, token: &str) -> String {
    format!(
        "Authorization: Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{sid}:{token}"))
    )
}

fn twilio(method: &str, url: &str, sid: &str, token: &str) -> Result<Value> {
    call(&Call {
        method,
        url,
        header: &header(sid, token),
        form: &[],
        json: None,
    })
}

fn held(id: &str) -> Result<(String, String)> {
    let vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "rotate")?;
    let payload = vault.get_item(id)?;
    if payload["kind"] != json!(KIND) {
        bail!("{id} is a {} item; rotate --with twilio replaces an {KIND} item's {TOKEN}, with the Account SID in {SID}", payload["kind"]);
    }
    let text = |field: &str| {
        payload["fields"][field]
            .as_str()
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .with_context(|| format!("{id} holds no {field}"))
    };
    let sid = text(SID)?;
    if !sid.starts_with(SID_PREFIX) {
        bail!("{id}'s {SID} is {sid}, not a Twilio Account SID, which starts with {SID_PREFIX}");
    }
    Ok((sid, text(TOKEN)?))
}

fn rotate(id: &str) -> Result<Value> {
    let (sid, old) = held(id)?;
    let made = twilio("POST", &format!("{ACCOUNTS}/Secondary"), &sid, &old)?;
    let new = made["secondary_auth_token"]
        .as_str()
        .context("Twilio answered no secondary_auth_token")?
        .to_string();
    let take_back = || twilio("DELETE", &format!("{ACCOUNTS}/Secondary"), &sid, &old);
    let revision = match crate::runtime::revise::fields(id, &[(TOKEN, &new)]) {
        Ok(revision) => revision,
        Err(error) => {
            return match take_back() {
                Ok(_) => Err(error.context(format!("{id} could not store the new token, so Twilio's secondary token was deleted again; the old one still works"))),
                Err(undo) => Err(error.context(format!("{id} could not store the new token and Twilio's secondary token could not be deleted ({undo:#}); delete it in the Twilio console"))),
            };
        }
    };
    let proved = twilio("GET", &format!("{API}/{sid}.json"), &sid, &new)
        .and_then(|_| twilio("POST", &format!("{ACCOUNTS}/Promote"), &sid, &new));
    if let Err(error) = proved {
        crate::runtime::audit::append(
            "twilio-rotate-failed",
            &json!({"item": id, "account": sid, "revision": revision}),
        )?;
        let undone = take_back();
        let restored = crate::runtime::revise::fields(id, &[(TOKEN, &old)]);
        match (undone, restored) {
            (Ok(_), Ok(back)) => bail!("{error:#}; the secondary token was deleted again and {id} holds the old token again at revision {back}, which still works"),
            (Err(undo), Ok(back)) => bail!("{error:#}; {id} holds the old token again at revision {back}, but the secondary token could not be deleted ({undo:#}); delete it in the Twilio console"),
            (_, Err(undo)) => bail!("{error:#}; {id} keeps the secondary token at revision {revision}, as the old one could not be written back ({undo:#}); it is the saved version before it"),
        }
    }
    crate::runtime::audit::append(
        "twilio-token-rotated",
        &json!({"item": id, "account": sid, "revision": revision}),
    )?;
    Ok(json!({
        "ok": true,
        "item": id,
        "account": sid,
        "revision": revision,
        "next": "the old auth token no longer signs in; every program signed in with it must read the new one from the vault",
    }))
}
