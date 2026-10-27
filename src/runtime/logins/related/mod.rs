// The sites that share one sign-in with the sites a login names — one account
// for several domains, such as a service and its regional or renamed
// addresses — from Password Manager Resources, the list of site quirks
// password managers maintain together
// (https://github.com/apple/password-manager-resources). Its
// shared-credentials file holds groups of sites sharing one account
// ("shared") and moves of sign-in from old sites to new ones ("from" to
// "to"). The file is downloaded whole, so nothing from the vault is sent.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::process::Command;

use crate::core::items::domain_matches;

/// Each site's change-password page, as the same project lists them.
pub(crate) mod change;

/// The shared-credentials quirks file of Password Manager Resources.
pub(crate) const SHARED_URL: &str =
    "https://raw.githubusercontent.com/apple/password-manager-resources/main/quirks/shared-credentials.json";

fn groups() -> Result<Vec<Value>> {
    let response = stado_wait::output(Command::new("curl").args(["-sS", "--fail", SHARED_URL]))
        .context("curl the Password Manager Resources shared credentials")?;
    if !response.status.success() {
        bail!(
            "the shared credentials of Password Manager Resources at {SHARED_URL} could not be read ({}): {}; no site was added",
            response.status,
            String::from_utf8_lossy(&response.stderr).trim()
        );
    }
    match serde_json::from_slice(&response.stdout)
        .with_context(|| format!("the shared credentials at {SHARED_URL} are not JSON"))?
    {
        Value::Array(groups) => Ok(groups),
        _ => bail!("the shared credentials at {SHARED_URL} are not a list of groups"),
    }
}

fn hosts<'v>(group: &'v Value, key: &str) -> impl Iterator<Item = &'v str> {
    group.get(key).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str)
}

/// The sites sharing a sign-in with any of `sites` that `sites` does not
/// already name: every member of a shared group one of them belongs to, and
/// the new sites a move takes sign-in to from one of them. A move only goes
/// forward, so a login on a new site gains nothing from the old ones.
pub(crate) fn of(sites: &[String]) -> Result<Vec<String>> {
    let names = |listed: &str| sites.iter().any(|site| domain_matches(listed, site));
    let mut related = Vec::new();
    for group in groups()? {
        let shared: Vec<&str> = hosts(&group, "shared").collect();
        let from: Vec<&str> = hosts(&group, "from").collect();
        let gained: Vec<&str> = if shared.iter().any(|listed| names(listed)) {
            shared
        } else if from.iter().any(|listed| names(listed)) {
            hosts(&group, "to").collect()
        } else {
            continue;
        };
        for host in gained {
            if !names(host) && !related.iter().any(|known: &String| known == host) {
                related.push(host.to_string());
            }
        }
    }
    Ok(related)
}
