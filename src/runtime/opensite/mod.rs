// `skarbiec open <id> [--site <domain>] [--change-password]`: open a login's
// site in the default browser — where autofill offers the login — or its
// change-password page, as the desktop's Open <site> and Change password at
// buttons do. A login offered on several sites names one with --site; nothing
// is read from the item but its sites.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;

use crate::cli::args::{flag_set, Usage};

const USAGE: &str = "usage: open <login-id> [--site <domain>] [--change-password]";

/// The program that hands an address to the desktop's default browser.
#[cfg(target_os = "macos")]
const OPENER: &str = "open";
#[cfg(not(target_os = "macos"))]
const OPENER: &str = "xdg-open";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "open" {
        return Ok(None);
    }
    let [id] = positionals else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let read = crate::runtime::dispatch("sites", &HashMap::new(), &[id.clone()])?
        .context("sites answered nothing")?;
    let sites: Vec<&str> = read["domains"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let site = match (flags.get("site"), sites.as_slice()) {
        (Some(named), _) if sites.contains(&named.as_str()) => named.as_str(),
        (Some(named), _) => bail!(
            "{id} is not offered on {named}; its sites are: {}",
            sites.join(", ")
        ),
        (None, [only]) => only,
        (None, []) => {
            bail!("{id} names no site to open; `skarbiec sites {id} --add <domain>` names one")
        }
        (None, several) => bail!(
            "{id} is offered on {}; name one with --site",
            several.join(", ")
        ),
    };
    let address = if flag_set(flags, "change-password") {
        format!("https://{site}/.well-known/change-password")
    } else {
        format!("https://{site}/")
    };
    let opened = stado_wait::output(Command::new(OPENER).arg(&address))
        .with_context(|| format!("run {OPENER}"))?;
    if !opened.status.success() {
        bail!(
            "{OPENER} could not open {address} ({}): {}",
            opened.status,
            String::from_utf8_lossy(&opened.stderr).trim()
        );
    }
    Ok(Some(json!({"ok": true, "item": id, "opened": address})))
}
