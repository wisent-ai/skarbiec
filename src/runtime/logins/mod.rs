// Which logins a site fills: the owner-side view of the browser host's
// question. Each live login's context names the domains it is for; a login
// for `example.com` fills `example.com` and its subdomains, never a host that
// merely ends in the same letters. Passwords and one-time codes stay out of
// the answer; the username is the owner's to see.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::items::{domain_matches, item_domains, site_host};
use crate::core::{schema, vault::Vault, vault_path};

/// The kind the browser host fills from.
const LOGIN_KIND: &str = "login";

mod codes;
mod create;
mod pick;
mod related;
mod sites;

pub use sites::set_from_body as set_sites_from_body;

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command == "sites" {
        return sites::run(flags, positionals).map(Some);
    }
    if command == "totp" {
        return match crate::cli::args::verb(command, positionals, "totp", "missing") {
            Some([]) => codes::run().map(Some),
            Some(_) => Err(crate::cli::args::Usage("usage: totp missing".to_string()).into()),
            None => Ok(None),
        };
    }
    if command != "login" {
        return Ok(None);
    }
    match positionals.split_first() {
        Some((verb, rest)) if verb == "list" => logins_for(rest).map(Some),
        Some((verb, rest)) if verb == "new" => create::run(flags, rest).map(Some),
        Some((verb, rest)) if verb == "get" => pick::run(flags, rest).map(Some),
        _ => Ok(None),
    }
}

/// The live logins autofill offers on no site, because their context names
/// none, and the ones that would not open to tell; review lists them under
/// logins_offered_nowhere, and `sites <id> --add` gives one a site.
pub fn offered_nowhere() -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    let mut nowhere = Vec::new();
    let mut unreadable = Vec::new();
    for entry in vault.list(false) {
        if entry.get("kind").and_then(Value::as_str) != Some(LOGIN_KIND) {
            continue;
        }
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        match vault.get_item(id) {
            Ok(payload) => {
                let named = payload
                    .get("context")
                    .is_some_and(|context| !item_domains(context).is_empty());
                if !named {
                    nowhere.push(id.to_string());
                }
            }
            Err(error) => unreadable.push(json!({"item": id, "error": format!("{error:#}")})),
        }
    }
    Ok(json!({"logins": nowhere, "unreadable": unreadable}))
}

/// `skarbiec login list <site>`: the site is a host or a whole address.
///
/// A login that will not open is listed under `unreadable` with its error,
/// because leaving it out would read as "no login for this site" when one
/// may be there. Logins whose context states no domain are listed under
/// `without_domain`: the browser host offers them on no site.
fn logins_for(positionals: &[String]) -> Result<Value> {
    let Some(site) = positionals.first().filter(|site| !site.trim().is_empty()) else {
        return Err(crate::cli::args::Usage(
            "usage: login list <host or address>, such as github.com or https://github.com/login"
                .to_string(),
        )
        .into());
    };
    let host = site_host(site);
    if host.is_empty() {
        return Err(crate::cli::args::Usage(format!("{site} names no host")).into());
    }
    let vault = Vault::open(vault_path())?;
    let mut logins = Vec::new();
    let mut unreadable = Vec::new();
    let mut without_domain = Vec::new();
    for entry in vault.list(false) {
        if entry.get("kind").and_then(Value::as_str) != Some(LOGIN_KIND) {
            continue;
        }
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        let payload = match vault.get_item(id) {
            Ok(payload) => payload,
            Err(error) => {
                unreadable.push(json!({"item": id, "error": format!("{error:#}")}));
                continue;
            }
        };
        // A login with no context states no domain, the same as a context
        // that names none: both are offered on no site.
        let domains = match payload.get("context") {
            Some(context) => item_domains(context),
            None => Vec::new(),
        };
        if domains.is_empty() {
            without_domain.push(id.to_string());
            continue;
        }
        if !domains.iter().any(|domain| domain_matches(domain, &host)) {
            continue;
        }
        let username = match schema::fields(&payload) {
            Ok(fields) => fields
                .get("username")
                .and_then(Value::as_str)
                .map(str::to_string),
            Err(error) => {
                unreadable.push(json!({"item": id, "error": format!("{error:#}")}));
                continue;
            }
        };
        logins.push(json!({
            "item": id,
            "name": payload.get("context").and_then(crate::core::items::display_name),
            "username": username,
            "domains": domains,
        }));
    }
    Ok(json!({
        "ok": true,
        "host": host,
        "logins": logins,
        "without_domain": without_domain,
        "unreadable": unreadable,
    }))
}
