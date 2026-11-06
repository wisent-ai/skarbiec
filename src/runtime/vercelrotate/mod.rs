// The vercel adapter of `skarbiec rotate <id> --with vercel [--days <N>]`: replace a Vercel access token a
// token item keeps through Vercel's own API. Signed in with it, Vercel names
// the token itself (/v5/user/tokens/current) and makes a new one with the
// same name — for the same team when the old one was scoped to one — ending
// --days days from now when given. The vault stores the new token as the
// item's next revision; the new token reads the account (/v2/user), proving
// Vercel takes it; then the new token deletes the old one. Before that
// delete nothing has ended: a failure deletes the new token again and
// writes the old one back. Tokens reach curl only as a header on its
// standard input; the answer names the token's name and id, never a token.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::Usage;
use crate::core::{vault::Vault, vault_path};
use crate::runtime::apicall::{call, Call};

pub(crate) const USAGE: &str = "usage: rotate <id> --with vercel [--days <N>]";
const KIND: &str = "token";
const FIELD: &str = "token";
const API: &str = "https://api.vercel.com";

/// Replace `id`'s Vercel token, as `rotate <id> --with vercel` asks.
pub(crate) fn rotate_item(flags: &HashMap<String, String>, id: &str) -> Result<Value> {
    let days = match flags.get("days") {
        Some(days) => Some(days.parse::<i64>().map_err(|_| {
            Usage(format!(
                "--days {days} is not a whole number of days; {USAGE}"
            ))
        })?),
        None => None,
    };
    rotate(id, days)
}

fn vercel(method: &str, path: &str, token: &str, body: Option<&Value>) -> Result<Value> {
    call(&Call {
        method,
        url: &format!("{API}{path}"),
        header: &format!("Authorization: Bearer {token}"),
        form: &[],
        json: body,
    })
}

fn held(id: &str) -> Result<String> {
    let vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "rotate")?;
    let payload = vault.get_item(id)?;
    if payload["kind"] != json!(KIND) {
        bail!(
            "{id} is a {} item; rotate --with vercel replaces a {KIND} item's {FIELD}",
            payload["kind"]
        );
    }
    payload["fields"][FIELD]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .with_context(|| format!("{id} holds no {FIELD}"))
}

/// The milliseconds since the epoch `days` days from now, as Vercel's
/// expiresAt takes them.
fn ends(days: i64) -> i128 {
    (time::OffsetDateTime::now_utc() + time::Duration::days(days)
        - time::OffsetDateTime::UNIX_EPOCH)
        .whole_milliseconds()
}

fn rotate(id: &str, days: Option<i64>) -> Result<Value> {
    let old = held(id)?;
    let current = vercel("GET", "/v5/user/tokens/current", &old, None)
        .context("Vercel did not name the stored token; it may have ended or been deleted")?;
    let old_id = current["token"]["id"]
        .as_str()
        .context("Vercel answered the current token without its id")?
        .to_string();
    let name = current["token"]["name"]
        .as_str()
        .context("Vercel answered the current token without its name")?
        .to_string();
    let team = current["token"]["scopes"]
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|scope| scope["teamId"].as_str())
        .map(|team| format!("?teamId={team}"));
    let mut body = json!({"name": name});
    if let Some(days) = days {
        body["expiresAt"] = json!(ends(days));
    }
    let created_path = match &team {
        Some(query) => format!("/v3/user/tokens{query}"),
        None => "/v3/user/tokens".to_string(),
    };
    let made = vercel("POST", &created_path, &old, Some(&body))?;
    let new = made["bearerToken"]
        .as_str()
        .context("Vercel answered no bearerToken")?
        .to_string();
    let new_id = made["token"]["id"]
        .as_str()
        .context("Vercel answered the new token without its id")?
        .to_string();
    let take_back = || vercel("DELETE", &format!("/v3/user/tokens/{new_id}"), &old, None);
    let revision = match crate::runtime::revise::fields(id, &[(FIELD, &new)]) {
        Ok(revision) => revision,
        Err(error) => {
            return match take_back() {
                Ok(_) => Err(error.context(format!("{id} could not store the new token, so Vercel's new token was deleted again; the old one still works"))),
                Err(undo) => Err(error.context(format!("{id} could not store the new token and Vercel's new token {new_id} could not be deleted ({undo:#}); delete it in Vercel's account settings"))),
            };
        }
    };
    let proved = vercel("GET", "/v2/user", &new, None)
        .and_then(|_| vercel("DELETE", &format!("/v3/user/tokens/{old_id}"), &new, None));
    if let Err(error) = proved {
        crate::runtime::audit::append(
            "vercel-rotate-failed",
            &json!({"item": id, "name": name, "revision": revision}),
        )?;
        let undone = take_back();
        let restored = crate::runtime::revise::fields(id, &[(FIELD, &old)]);
        match (undone, restored) {
            (Ok(_), Ok(back)) => bail!("{error:#}; the new token was deleted again and {id} holds the old token again at revision {back}, which still works"),
            (Err(undo), Ok(back)) => bail!("{error:#}; {id} holds the old token again at revision {back}, but the new token {new_id} could not be deleted ({undo:#}); delete it in Vercel's account settings"),
            (_, Err(undo)) => bail!("{error:#}; {id} keeps the new token at revision {revision}, as the old one could not be written back ({undo:#}); it is the saved version before it"),
        }
    }
    crate::runtime::audit::append(
        "vercel-token-rotated",
        &json!({"item": id, "name": name, "token_id": new_id, "revision": revision}),
    )?;
    Ok(json!({
        "ok": true,
        "item": id,
        "name": name,
        "token_id": new_id,
        "team": team.is_some(),
        "expires_at": made["token"]["expiresAt"],
        "revision": revision,
        "next": "the old token is deleted in Vercel; every program deploying with it must read the new one from the vault",
    }))
}
