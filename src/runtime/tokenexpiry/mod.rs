// `skarbiec expiry tokens [--before <iso8601>]`: the stored JSON Web Tokens
// and when each runs out. A JWT carries its own end in its `exp` claim, so a
// token kept in the vault can be found expired, or about to, before the
// program using it fails. Every text field of every live item is looked at;
// a value of three dot-separated base64url parts is read as a JWT, and one
// that has that shape but does not decode to a header naming an `alg` and a
// claims object is named under `malformed` with why. Only the item, the
// field, the issuer and the moments leave — never the token, its subject or
// any other claim. Nothing is verified: the vault holds no issuer key, and
// the moments are what the token says of itself.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::cli::args::Usage;
use crate::core::{clock, schema, vault::Vault, vault_path};

const USAGE: &str = "usage: expiry tokens [--before <iso8601>]";

/// `expiry tokens`, as the expiry command hands it over with what follows
/// the verb.
pub(crate) fn report(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    if !positionals.is_empty() {
        return Err(Usage(USAGE.to_string()).into());
    }
    let before = flags.get("before");
    if let Some(moment) = before.filter(|moment| !clock::is_iso(moment)) {
        return Err(Usage(format!("--before {moment} is not a UTC time of the form {}; {USAGE}", clock::now_iso())).into());
    }
    let now = clock::now_iso();
    let vault = Vault::open(vault_path())?;
    let mut tokens = Vec::new();
    let mut malformed = Vec::new();
    let mut unreadable = Vec::new();
    for entry in vault.list(false) {
        let Some(id) = entry.get("id").and_then(Value::as_str) else { continue };
        if entry.get("state").and_then(Value::as_str) != Some("active") {
            continue;
        }
        let opened = vault.get_item(id).and_then(|payload| schema::fields(&payload).cloned());
        let fields = match opened {
            Ok(fields) => fields,
            Err(error) => {
                unreadable.push(json!({"item": id, "error": format!("{error:#}")}));
                continue;
            }
        };
        for (field, value) in &fields {
            let Some((header, payload)) = value.as_str().and_then(shaped) else { continue };
            let claims = match claims(header, payload) {
                Ok(claims) => claims,
                Err(error) => {
                    malformed.push(json!({"item": id, "field": field, "error": format!("{error:#}")}));
                    continue;
                }
            };
            let moment = |claim: &str| claims.get(claim).and_then(Value::as_i64).and_then(clock::iso_at);
            let expires_at = moment("exp");
            if let (Some(limit), Some(end)) = (before, expires_at.as_ref()) {
                if end.as_str() >= limit.as_str() {
                    continue;
                }
            }
            tokens.push(json!({
                "item": id,
                "field": field,
                "issuer": claims.get("iss"),
                "issued_at": moment("iat"),
                "expires_at": expires_at,
                "expired": expires_at.as_ref().is_some_and(|end| end.as_str() <= now.as_str()),
            }));
        }
    }
    // Soonest end first; a token that states no end runs last, as it never
    // runs out by itself.
    tokens.sort_by(|left, right| {
        let end = |token: &Value| token["expires_at"].as_str().map(str::to_string);
        match (end(left), end(right)) {
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });
    Ok(json!({
        "ok": malformed.is_empty() && unreadable.is_empty(),
        "now": now,
        "before": before,
        "tokens": tokens,
        "malformed": malformed,
        "unreadable": unreadable,
    }))
}

/// The header and payload of a value shaped as a JWT: three non-empty
/// dot-separated parts of base64url characters whose first two encode JSON
/// objects — base64url of `{"` is `eyJ`, so a host name such as
/// db.example.com, three parts too, is not taken for one.
fn shaped(value: &str) -> Option<(&str, &str)> {
    const OBJECT: &str = "eyJ";
    let base64url = |part: &str| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    let mut parts = value.trim().split('.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    let shape = parts.next().is_none()
        && header.starts_with(OBJECT)
        && payload.starts_with(OBJECT)
        && base64url(header)
        && base64url(payload)
        && base64url(signature);
    shape.then_some((header, payload))
}

fn claims(header: &str, payload: &str) -> Result<Map<String, Value>> {
    let header = decode(header, "header")?;
    if header.get("alg").and_then(Value::as_str).is_none() {
        bail!("its header names no alg, so it is not a JSON Web Token");
    }
    match decode(payload, "payload")? {
        Value::Object(claims) => Ok(claims),
        other => bail!("its payload is {other}, not an object of claims"),
    }
}

fn decode(part: &str, name: &str) -> Result<Value> {
    let bytes = URL_SAFE_NO_PAD.decode(part).with_context(|| format!("its {name} is not base64url"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("its {name} is not JSON"))
}
