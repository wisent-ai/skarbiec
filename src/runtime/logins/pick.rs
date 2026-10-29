// `login get <site> --field <field> [--username <name>]`: read one field of
// the login a site is signed in with, without knowing its item id — what a
// script that logs in somewhere asks. The login is chosen as autofill
// chooses it; when the site has several, --username names which, and an
// ambiguous or empty choice is refused naming the logins it could be.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::{OrUsage, Usage};
use crate::core::{schema, vault::Vault, vault_path};

const USAGE: &str =
    "usage: login get <host or address> --field <field|one-time-code> [--username <name>]";
/// Not a stored field: `--field one-time-code` reads the code the login's
/// seed gives now.
const ONE_TIME_CODE: &str = "one-time-code";

pub(super) fn run(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let [site] = positionals else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let field = flags.get("field").or_usage(USAGE)?;
    let found = super::logins_for(positionals)?;
    let host = found["host"]
        .as_str()
        .context("login list answered no host")?
        .to_string();
    let offered: Vec<&Value> = found["logins"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|login| match flags.get("username") {
            Some(username) => login["username"].as_str() == Some(username.as_str()),
            None => true,
        })
        .collect();
    let unreadable = found["unreadable"].as_array().into_iter().flatten().count();
    let item = match offered.as_slice() {
        [only] => only["item"]
            .as_str()
            .context("a login offered on the site records no id")?
            .to_string(),
        [] => bail!(
            "no login{} is offered on {host}{}; login list {site} lists what is",
            match flags.get("username") {
                Some(username) => format!(" with username {username}"),
                None => String::new(),
            },
            match unreadable {
                count if count > Default::default() =>
                    format!(", and {count} logins would not open to tell"),
                _ => String::new(),
            }
        ),
        several => bail!(
            "{} logins are offered on {host}: {}; name one with --username",
            several.len(),
            several
                .iter()
                .map(|login| format!("{} ({})", login["item"], login["username"]))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let value = match field.as_str() {
        ONE_TIME_CODE => current_code(&item)?,
        _ => {
            let payload = Vault::open(vault_path())?.get_item(&item)?;
            schema::field(&payload, field)?
                .as_str()
                .with_context(|| format!("{item}'s {field} is not text"))?
                .to_string()
        }
    };
    crate::runtime::audit::append(
        "site-get",
        &json!({"item": item, "field": field, "site": host}),
    )?;
    Ok(json!({"ok": true, "site": host, "item": item, "field": field, "value": value}))
}

/// The code the login's seed gives now, as `totp code <id>` computes it, or the
/// reason it gives none.
fn current_code(item: &str) -> Result<String> {
    let answer = crate::runtime::dispatch(
        "totp",
        &HashMap::new(),
        &["code".to_string(), item.to_string()],
    )?
    .context("totp code answered nothing")?;
    match answer["code"].as_str() {
        Some(code) => Ok(code.to_string()),
        None => bail!("{item} gives no one-time code: {}", answer["reason"]),
    }
}
