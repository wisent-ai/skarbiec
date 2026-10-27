// `skarbiec totp missing`: the logins whose site offers authenticator codes
// (TOTP, RFC 6238) that keep no seed here, so their account is guarded by the
// password alone when a second factor is one setting away. Which sites offer
// codes is the 2FA Directory's answer, read from its published TOTP list; the
// answer carries the site's own setup page where the directory names one and
// the directory's attribution. Only the list of sites is downloaded: nothing
// from the vault leaves this host, and passwords and seeds stay out of the
// answer.

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use std::process::Command;

use crate::core::items::{domain_matches, item_domains};
use crate::core::{vault::Vault, vault_path};

use super::LOGIN_KIND;

/// The 2FA Directory's list of sites offering RFC 6238 codes, API version 4:
/// https://2fa.directory/api
const DIRECTORY_TOTP_URL: &str = "https://api.2fa.directory/v4/totp.json";
/// The attribution the directory's MIT license asks for wherever its data is
/// shown: https://2fa.directory/api
const ATTRIBUTION: &str = "Data sourced from 2FA Directory (https://2fa.directory/) by 2factorauth (https://github.com/2factorauth/).";

/// The directory's sites, domain -> entry; a refusal names the address and
/// curl's own reason, because without it nothing can be said.
fn directory() -> Result<Map<String, Value>> {
    let response = stado_wait::output(Command::new("curl").args(["-sS", "--fail", DIRECTORY_TOTP_URL]))
        .context("curl the 2FA Directory")?;
    if !response.status.success() {
        anyhow::bail!(
            "the 2FA Directory at {DIRECTORY_TOTP_URL} could not be read ({}): {}; no login was judged",
            response.status,
            String::from_utf8_lossy(&response.stderr).trim()
        );
    }
    let parsed: Value = serde_json::from_slice(&response.stdout)
        .with_context(|| format!("the 2FA Directory at {DIRECTORY_TOTP_URL} answered something that is not JSON"))?;
    match parsed {
        Value::Object(sites) => Ok(sites),
        other => anyhow::bail!(
            "the 2FA Directory at {DIRECTORY_TOTP_URL} answered {} instead of an object of sites",
            match other {
                Value::Array(_) => "a list",
                _ => "a single value",
            }
        ),
    }
}

/// Whether the payload keeps a usable authenticator seed.
fn holds_seed(payload: &Value) -> bool {
    payload
        .get("fields")
        .and_then(|fields| fields.get("totp_secret"))
        .and_then(Value::as_str)
        .is_some_and(|seed| !seed.trim().is_empty())
}

pub(super) fn run() -> Result<Value> {
    let sites = directory()?;
    let vault = Vault::open(vault_path())?;
    let mut missing = Vec::new();
    let mut unreadable = Vec::new();
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
        if holds_seed(&payload) {
            continue;
        }
        let domains = payload.get("context").map(item_domains).into_iter().flatten();
        let offered: Vec<Value> = domains
            .filter_map(|domain| {
                sites
                    .iter()
                    .find(|(site, _)| domain_matches(site, &domain))
                    .map(|(site, about)| json!({"site": site, "setup": about.get("documentation")}))
            })
            .collect();
        if !offered.is_empty() {
            missing.push(json!({"item": id, "sites": offered}));
        }
    }
    Ok(json!({
        "ok": missing.is_empty() && unreadable.is_empty(),
        "logins": missing,
        "unreadable": unreadable,
        "source": DIRECTORY_TOTP_URL,
        "attribution": ATTRIBUTION,
    }))
}
