// The sendgrid adapter of `skarbiec rotate <id> --with sendgrid`: replace a SendGrid API key a token item
// keeps through SendGrid's own API. A SendGrid key reads SG.<key id>.<secret>,
// so the stored key names itself: signed in with it, SendGrid answers that
// key's name and scopes, and makes a new key with the same name and scopes.
// The vault stores the new key as the item's next revision; the new key
// signs in, proving SendGrid takes it; then the new key deletes the old one.
// Before that delete nothing has ended: a failure deletes the new key again
// and writes the old one back. Keys reach curl only as a header on its
// standard input; the answer names the key's name and id, never a key.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{vault::Vault, vault_path};
use crate::runtime::apicall::{call, Call};

pub(crate) const USAGE: &str = "usage: rotate <id> --with sendgrid";
const KIND: &str = "token";
const FIELD: &str = "token";
const API: &str = "https://api.sendgrid.com/v3";
/// What every SendGrid API key starts with, before its id and secret.
const PREFIX: &str = "SG";

/// Replace `id`'s SendGrid key, as `rotate <id> --with sendgrid` asks.
pub(crate) fn rotate_item(_flags: &HashMap<String, String>, id: &str) -> Result<Value> {
    rotate(id)
}

fn sendgrid(method: &str, path: &str, key: &str, body: Option<&Value>) -> Result<Value> {
    call(&Call { method, url: &format!("{API}{path}"), header: &format!("Authorization: Bearer {key}"), form: &[], json: body })
}

/// The key id a SendGrid key carries between its prefix and its secret.
fn key_id(key: &str) -> Option<String> {
    let mut parts = key.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(PREFIX), Some(id), Some(secret), None) if !id.is_empty() && !secret.is_empty() => Some(id.to_string()),
        _ => None,
    }
}

fn held(id: &str) -> Result<(String, String)> {
    let vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "rotate")?;
    let payload = vault.get_item(id)?;
    if payload["kind"] != json!(KIND) {
        bail!("{id} is a {} item; rotate --with sendgrid replaces a {KIND} item's {FIELD}", payload["kind"]);
    }
    let key = payload["fields"][FIELD].as_str().filter(|value| !value.is_empty()).with_context(|| format!("{id} holds no {FIELD}"))?;
    let Some(key_id) = key_id(key) else {
        bail!("{id}'s {FIELD} is not a SendGrid API key, which reads {PREFIX}.<key id>.<secret>");
    };
    Ok((key.to_string(), key_id))
}

fn rotate(id: &str) -> Result<Value> {
    let (old, old_id) = held(id)?;
    let current = sendgrid("GET", &format!("/api_keys/{old_id}"), &old, None)
        .context("SendGrid did not answer the key's own name and scopes; a key needs API Keys access to replace itself")?;
    let name = current["name"].as_str().context("SendGrid answered the key without its name")?.to_string();
    let scopes = current["scopes"].as_array().filter(|scopes| !scopes.is_empty()).context("SendGrid answered the key without its scopes")?.clone();
    let made = sendgrid("POST", "/api_keys", &old, Some(&json!({"name": name, "scopes": scopes})))?;
    let new = made["api_key"].as_str().context("SendGrid answered no api_key")?.to_string();
    let new_id = made["api_key_id"].as_str().context("SendGrid answered no api_key_id")?.to_string();
    let take_back = || sendgrid("DELETE", &format!("/api_keys/{new_id}"), &old, None);
    let revision = match crate::runtime::revise::fields(id, &[(FIELD, &new)]) {
        Ok(revision) => revision,
        Err(error) => {
            return match take_back() {
                Ok(_) => Err(error.context(format!("{id} could not store the new key, so SendGrid's new key was deleted again; the old one still works"))),
                Err(undo) => Err(error.context(format!("{id} could not store the new key and SendGrid's new key {new_id} could not be deleted ({undo:#}); delete it in SendGrid's settings"))),
            };
        }
    };
    let proved = sendgrid("GET", "/scopes", &new, None).and_then(|_| sendgrid("DELETE", &format!("/api_keys/{old_id}"), &new, None));
    if let Err(error) = proved {
        crate::runtime::audit::append("sendgrid-rotate-failed", &json!({"item": id, "name": name, "revision": revision}))?;
        let undone = take_back();
        let restored = crate::runtime::revise::fields(id, &[(FIELD, &old)]);
        match (undone, restored) {
            (Ok(_), Ok(back)) => bail!("{error:#}; the new key was deleted again and {id} holds the old key again at revision {back}, which still works"),
            (Err(undo), Ok(back)) => bail!("{error:#}; {id} holds the old key again at revision {back}, but the new key {new_id} could not be deleted ({undo:#}); delete it in SendGrid's settings"),
            (_, Err(undo)) => bail!("{error:#}; {id} keeps the new key at revision {revision}, as the old one could not be written back ({undo:#}); it is the saved version before it"),
        }
    }
    crate::runtime::audit::append("sendgrid-key-rotated", &json!({"item": id, "name": name, "key_id": new_id, "revision": revision}))?;
    Ok(json!({
        "ok": true,
        "item": id,
        "name": name,
        "key_id": new_id,
        "scopes": scopes.len(),
        "revision": revision,
        "next": "the old key is deleted in SendGrid; every program that sent with it must read the new one from the vault",
    }))
}
