// The gitlab adapter of `skarbiec rotate <id> --with gitlab --url <https://gitlab.example.com>
// [--expires-at <YYYY-MM-DD>]`: rotate a GitLab access token a token item
// keeps, through GitLab's own self-rotation
// (POST /api/v4/personal_access_tokens/self/rotate), which revokes the token
// it is called with and answers a new one with the same scopes. The new
// token is stored as the item's next revision, so the old one stays in its
// saved versions, then GitLab is asked who the new token is to prove it.
// The token reaches curl only on its standard input, as a header, never in
// an argument. GitLab has revoked the old token once it answers, so when the
// vault cannot take the new one it is written to an owner-only file beside
// the vault, named in the refusal, rather than lost.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::{OrUsage, Usage};
use crate::core::{vault::Vault, vault_path};

pub(crate) const USAGE: &str = "usage: rotate <id> --with gitlab --url <https://gitlab.example.com> [--expires-at <YYYY-MM-DD>]";
const FIELD: &str = "token";

/// Rotate `id`'s GitLab token, as `rotate <id> --with gitlab` asks.
pub(crate) fn rotate_item(flags: &HashMap<String, String>, id: &str) -> Result<Value> {
    let url = flags.get("url").or_usage(USAGE)?.trim_end_matches('/');
    if !url.starts_with("https://") || url.contains('@') {
        return Err(Usage(format!("--url {url} is not an https:// GitLab address without a user in it. {USAGE}")).into());
    }
    rotate(id, url, flags.get("expires-at"))
}

/// Call GitLab's API at `path` signed in with `token`.
fn gitlab(url: &str, path: &str, token: &str, method: &str, form: &[String]) -> Result<Value> {
    let endpoint = format!("{url}/api/v4/{path}");
    let header = format!("PRIVATE-TOKEN: {token}");
    crate::runtime::apicall::call(&crate::runtime::apicall::Call { method, url: &endpoint, header: &header, form, json: None })
        .with_context(|| format!("GitLab refused {method} {path}"))
}

fn rotate(id: &str, url: &str, expires_at: Option<&String>) -> Result<Value> {
    let old = {
        let vault = Vault::open(vault_path())?;
        crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "rotate")?;
        let payload = vault.get_item(id)?;
        if payload["kind"] != json!("token") {
            bail!("{id} is a {} item; rotate --with gitlab replaces the token a token item keeps", payload["kind"]);
        }
        payload["fields"][FIELD].as_str().filter(|token| !token.is_empty()).with_context(|| format!("{id} holds no {FIELD}"))?.to_string()
    };
    let form: Vec<String> = expires_at.map(|date| format!("expires_at={date}")).into_iter().collect();
    let rotated = gitlab(url, "personal_access_tokens/self/rotate", &old, "POST", &form)?;
    let new = rotated["token"].as_str().context("GitLab rotated the token but answered no new one")?.to_string();
    let expires = rotated["expires_at"].clone();
    let revision = crate::runtime::revise::issued(id, FIELD, &new, "GitLab")?;
    let proven = gitlab(url, "personal_access_tokens/self", &new, "GET", &[])
        .with_context(|| format!("{id} holds GitLab's new token at revision {revision}, but GitLab did not answer for it"))?;
    // The token's last day becomes the item's recorded expiry, so review and
    // expiry list warn before it runs out. The token is rotated and stored
    // already, so a date that cannot be recorded is said, not raised.
    let expiry = match expires.as_str() {
        Some(day) => match midnight(day).and_then(|on| crate::runtime::expiry::set(id, &on)) {
            Ok(set) => set,
            Err(error) => json!({"recorded": false, "error": format!("{error:#}")}),
        },
        None => Value::Null,
    };
    crate::runtime::audit::append(
        "gitlab-token-rotated",
        &json!({"item": id, "url": url, "token_id": proven["id"], "expires_at": expires, "revision": revision}),
    )?;
    Ok(json!({"ok": true, "item": id, "url": url, "name": proven["name"], "scopes": proven["scopes"], "expires_at": expires, "expiry": expiry, "revision": revision}))
}

/// The UTC moment a GitLab `YYYY-MM-DD` day starts, in the vault's stamp form.
fn midnight(day: &str) -> Result<String> {
    let parts: Vec<&str> = day.split('-').collect();
    let [year, month, date] = parts.as_slice() else {
        bail!("GitLab answered expires_at {day}, which is not a YYYY-MM-DD day");
    };
    let year: i32 = year.parse().with_context(|| format!("GitLab's expires_at {day} names no year"))?;
    let month: u8 = month.parse().with_context(|| format!("GitLab's expires_at {day} names no month"))?;
    let date: u8 = date.parse().with_context(|| format!("GitLab's expires_at {day} names no day"))?;
    let month = time::Month::try_from(month).with_context(|| format!("GitLab's expires_at {day} names no month"))?;
    let start = time::Date::from_calendar_date(year, month, date)
        .with_context(|| format!("GitLab's expires_at {day} is not a calendar day"))?
        .midnight()
        .assume_utc()
        .unix_timestamp();
    crate::core::clock::iso_at(start).with_context(|| format!("GitLab's expires_at {day} is outside the times the vault stamps"))
}
