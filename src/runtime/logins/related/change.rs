// Where each of a login's sites lets a person change the password: the page
// Password Manager Resources lists for the site
// (https://github.com/apple/password-manager-resources, its
// change-password-URLs file, downloaded whole so no site name leaves), else
// the well-known address sites publish for it (RFC 8615's registry names
// .well-known/change-password), which a site that lists none may still
// serve. Each answer says which of the two it is.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::core::items::domain_matches;

/// The change-password-URLs quirks file of Password Manager Resources.
const CHANGE_URL: &str =
    "https://raw.githubusercontent.com/apple/password-manager-resources/main/quirks/change-password-URLs.json";

fn listed() -> Result<Map<String, Value>> {
    let body = crate::net::https::get(
        CHANGE_URL,
        &[],
        "the change-password pages of Password Manager Resources",
    )?;
    match serde_json::from_slice(&body)
        .with_context(|| format!("the change-password pages at {CHANGE_URL} are not JSON"))?
    {
        Value::Object(sites) => Ok(sites),
        _ => bail!("the change-password pages at {CHANGE_URL} are not an object of sites"),
    }
}

/// One answer per site, in the order the login names them.
pub(crate) fn pages(sites: &[String]) -> Result<Vec<Value>> {
    let known = listed()?;
    Ok(sites
        .iter()
        .map(|site| {
            let found = known
                .iter()
                .find(|(listed, _)| domain_matches(listed, site))
                .and_then(|(_, page)| page.as_str());
            match found {
                Some(page) => json!({"site": site, "change_password": page, "source": CHANGE_URL}),
                None => json!({
                    "site": site,
                    "change_password": format!("https://{site}/.well-known/change-password"),
                    "source": "well-known",
                }),
            }
        })
        .collect())
}
