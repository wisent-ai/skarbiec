// `skarbiec password rules <id> --lookup`: the rules a login's site is known
// to enforce, from Password Manager Resources, the shared list of site quirks
// password managers maintain together
// (https://github.com/apple/password-manager-resources). Its password-rules
// file maps a site to the rules it enforces, in the same Password Rules
// language `--set` takes. The file is downloaded whole, so nothing from the
// vault is sent, not even a site name.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::process::Command;

use crate::core::items::{domain_matches, item_domains};
use crate::core::{vault::Vault, vault_path};

/// The password-rules quirks file of Password Manager Resources.
const RULES_URL: &str =
    "https://raw.githubusercontent.com/apple/password-manager-resources/main/quirks/password-rules.json";
/// The attribution the project's MIT licence asks for where its data is used.
const ATTRIBUTION: &str =
    "Password rules from Password Manager Resources (https://github.com/apple/password-manager-resources), MIT licence.";

fn registry() -> Result<Map<String, Value>> {
    let response = stado_wait::output(Command::new("curl").args(["-sS", "--fail", RULES_URL]))
        .context("curl the Password Manager Resources password rules")?;
    if !response.status.success() {
        bail!(
            "the password rules of Password Manager Resources at {RULES_URL} could not be read ({}): {}; no rules were recorded",
            response.status,
            String::from_utf8_lossy(&response.stderr).trim()
        );
    }
    match serde_json::from_slice(&response.stdout)
        .with_context(|| format!("the password rules at {RULES_URL} are not JSON"))?
    {
        Value::Object(sites) => Ok(sites),
        _ => bail!("the password rules at {RULES_URL} are not an object of sites"),
    }
}

/// Finds the rules the list holds for one of the login's sites and records
/// them as `--set` would, naming the site they were found under.
pub(super) fn lookup(id: &str) -> Result<Value> {
    let payload = Vault::open(vault_path())?.get_item(id)?;
    let sites = payload
        .get("context")
        .map(item_domains)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if sites.is_empty() {
        bail!("{id} names no site, so no site's rules can be looked up; `skarbiec sites {id} --add <domain>` names one");
    }
    let known = registry()?;
    let found = known
        .iter()
        .find(|(listed, _)| sites.iter().any(|site| domain_matches(listed, site)));
    let Some((listed, entry)) = found else {
        bail!(
            "Password Manager Resources lists no password rules for {}; `skarbiec password rules {id} --set '<rules>'` records the site's own",
            sites.join(", ")
        );
    };
    let rules = entry
        .get("password-rules")
        .and_then(Value::as_str)
        .with_context(|| {
            format!("the entry for {listed} at {RULES_URL} holds no password-rules text")
        })?;
    let mut answer = super::set(id, rules)?;
    answer["found_for"] = json!(listed);
    answer["password_rules"] = json!(rules.trim());
    answer["source"] = json!(RULES_URL);
    answer["attribution"] = json!(ATTRIBUTION);
    Ok(answer)
}
