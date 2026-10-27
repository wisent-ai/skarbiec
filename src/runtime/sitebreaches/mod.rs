// `skarbiec breach sites`: the logins whose site was breached after their
// password was set, so the password the breach may have taken is still the
// one in use. Which sites were breached, and when, is Have I Been Pwned's
// public list of breaches (https://haveibeenpwned.com/api/v3/breaches), which
// needs no key and is downloaded whole: nothing from the vault is sent, not
// even a site name. When each password was last set is `password age`'s
// answer. A login whose password changed after the breach is listed apart as
// changed since, so the list shows both what to do and what is done.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;

use crate::core::items::{domain_matches, item_domains};
use crate::core::{vault::Vault, vault_path};

/// Have I Been Pwned's list of every breach it holds, API version 3.
const BREACHES_URL: &str = "https://haveibeenpwned.com/api/v3/breaches";
/// The attribution the list's Creative Commons Attribution 4.0 licence asks
/// for wherever it is shown: https://haveibeenpwned.com/API/v3#License
const ATTRIBUTION: &str = "Breach data from Have I Been Pwned (https://haveibeenpwned.com), licensed CC BY 4.0.";

pub fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    let Some(rest) = crate::cli::args::verb(command, positionals, "breach", "sites") else {
        return Ok(None);
    };
    if !rest.is_empty() {
        return Err(crate::cli::args::Usage("usage: breach sites".to_string()).into());
    }
    report().map(Some)
}

fn breaches() -> Result<Vec<Value>> {
    // The API refuses a request that names no user agent.
    let response = stado_wait::output(Command::new("curl").args(["-sS", "--fail", "-A", "skarbiec", BREACHES_URL]))
        .context("curl the Have I Been Pwned breach list")?;
    if !response.status.success() {
        bail!(
            "the Have I Been Pwned breach list at {BREACHES_URL} could not be read ({}): {}; no login was judged",
            response.status,
            String::from_utf8_lossy(&response.stderr).trim()
        );
    }
    match serde_json::from_slice(&response.stdout)
        .with_context(|| format!("the breach list at {BREACHES_URL} is not JSON"))?
    {
        Value::Array(rows) => Ok(rows),
        _ => bail!("the breach list at {BREACHES_URL} is not a list of breaches"),
    }
}

fn text<'v>(row: &'v Value, key: &str) -> Option<&'v str> {
    row.get(key).and_then(Value::as_str).filter(|value| !value.is_empty())
}

/// One breach as the list states it: the site it hit, the day and its name.
/// A breach of no site, such as a leaked list of addresses, names no domain
/// and cannot be matched to a login, so it is passed over.
fn breach_of(row: &Value) -> Result<Option<(&str, &str, &str)>> {
    let Some(site) = text(row, "Domain") else {
        return Ok(None);
    };
    let name = text(row, "Name").with_context(|| format!("a breach of {site} in {BREACHES_URL} has no Name"))?;
    let when = text(row, "BreachDate")
        .with_context(|| format!("the breach {name} in {BREACHES_URL} has no BreachDate"))?;
    Ok(Some((site, when, name)))
}

fn report() -> Result<Value> {
    let breached = breaches()?
        .iter()
        .map(|row| breach_of(row).map(|found| found.map(|(s, w, n)| (s.to_string(), w.to_string(), n.to_string()))))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let ages = crate::runtime::age::report(None)?;
    let logins = ages.get("logins").and_then(Value::as_array).context("password age answered no logins")?;
    let vault = Vault::open(vault_path())?;
    let mut exposed = Vec::new();
    let mut changed = Vec::new();
    let mut unreadable = Vec::new();
    for age in logins {
        let id = text(age, "id").context("password age answered a login with no id")?;
        // password age names why it could not tell when a password was set.
        let Some(set) = text(age, "set_at") else {
            unreadable.push(json!({"item": id, "error": age.get("error")}));
            continue;
        };
        let payload = match vault.get_item(id) {
            Ok(payload) => payload,
            Err(error) => {
                unreadable.push(json!({"item": id, "error": format!("{error:#}")}));
                continue;
            }
        };
        let domains = payload.get("context").map(item_domains).into_iter().flatten().collect::<Vec<_>>();
        for (site, when, name) in &breached {
            if !domains.iter().any(|domain| domain_matches(site, domain)) {
                continue;
            }
            let row = json!({
                "item": id,
                "site": site,
                "breach": name,
                "breach_date": when,
                "password_set_at": set,
            });
            // The stamp and the breach day compare as text: both begin with
            // the year, month and day, and a password set on the day of the
            // breach counts as exposed.
            if set > when.as_str() && !set.starts_with(when.as_str()) {
                changed.push(row);
            } else {
                exposed.push(row);
            }
        }
    }
    Ok(json!({
        "ok": exposed.is_empty() && unreadable.is_empty(),
        "exposed": exposed,
        "changed_since": changed,
        "unreadable": unreadable,
        "source": BREACHES_URL,
        "attribution": ATTRIBUTION,
    }))
}
