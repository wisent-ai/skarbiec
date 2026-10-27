// The sites one login is for: read them, or replace them as a new revision.
// `login list` lists the logins that name no domain; this is how one is
// given its domains without rewriting the whole payload through set.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::OrUsage;
use crate::core::items::{item_domains, site_host};
use crate::core::{vault::Vault, vault_path};

const LOGIN_KIND: &str = "login";
const USAGE: &str = "usage: sites <login-id> [--set <domain[,domain...]> | --add <domain[,domain...]> | --remove <domain[,domain...]> | --add-related | --change-pages]";

/// `sites <id>` reads; `sites <id> --set a.com,b.com` replaces. An empty
/// `--set` clears them, and the login is then offered on no site. `--add`
/// and `--remove` change the list one site at a time, keeping the others;
/// `--add-related` adds the sites that share a sign-in with the ones named,
/// and `--change-pages` names where each site changes its password.
pub fn run(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let id = positionals.first().or_usage(USAGE)?;
    let related = crate::cli::args::flag_set(flags, "add-related");
    let pages = crate::cli::args::flag_set(flags, "change-pages");
    match (flags.get("set"), flags.get("add"), flags.get("remove"), related, pages) {
        (Some(listed), None, None, false, false) => set(id, bare_hosts("set", listed)?),
        (None, Some(listed), None, false, false) => change(id, bare_hosts("add", listed)?, Vec::new()),
        (None, None, Some(listed), false, false) => change(id, Vec::new(), bare_hosts("remove", listed)?),
        (None, None, None, true, false) => add_related(id),
        (None, None, None, false, true) => change_pages(id),
        (None, None, None, false, false) => read(id),
        _ => Err(crate::cli::args::Usage(format!(
            "name one of --set, --add, --remove, --add-related or --change-pages; {USAGE}"
        ))
        .into()),
    }
}

/// Where each of the login's sites changes its password, from the list
/// password managers share, else the site's well-known address; reads only.
fn change_pages(id: &str) -> Result<Value> {
    let payload = Vault::open(vault_path())?.get_item(id)?;
    login_kind(id, &payload)?;
    let sites = domains_of(&payload);
    if sites.is_empty() {
        bail!("{id} names no site, so there is no change-password page to find; `skarbiec sites {id} --add <domain>` names one");
    }
    Ok(json!({"ok": true, "item": id, "pages": super::related::change::pages(&sites)?}))
}

/// Adds the sites Password Manager Resources lists as sharing a sign-in with
/// the login's, naming them; a login whose sites share with none is refused,
/// since nothing would change.
fn add_related(id: &str) -> Result<Value> {
    let current = domains_of(&Vault::open(vault_path())?.get_item(id)?);
    if current.is_empty() {
        bail!("{id} names no site, so no related site can be found; `skarbiec sites {id} --add <domain>` names one");
    }
    let related = super::related::of(&current)?;
    if related.is_empty() {
        bail!(
            "Password Manager Resources lists no site sharing a sign-in with {}; nothing was added to {id}",
            current.join(", ")
        );
    }
    let mut answer = change(id, related.clone(), Vec::new())?;
    answer["related_added"] = json!(related);
    answer["source"] = json!(super::related::SHARED_URL);
    Ok(answer)
}

/// The login's sites with `added` appended where missing and `removed`
/// taken out; a site to remove that it does not name is refused with the
/// ones it does, since nothing would change.
fn change(id: &str, added: Vec<String>, removed: Vec<String>) -> Result<Value> {
    let current = domains_of(&Vault::open(vault_path())?.get_item(id)?);
    if let Some(absent) = removed.iter().find(|site| !current.contains(site)) {
        bail!("{id} is not offered on {absent}; its sites are: {}", current.join(", "));
    }
    let mut domains: Vec<String> = current.into_iter().filter(|site| !removed.contains(site)).collect();
    for site in added {
        if !domains.contains(&site) {
            domains.push(site);
        }
    }
    set(id, domains)
}

fn read(id: &str) -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    let payload = vault.get_item(id)?;
    login_kind(id, &payload)?;
    let domains = domains_of(&payload);
    // Where each site lets a person change the password, by the well-known
    // address sites publish for it (RFC 8615's registry names it), so a
    // rotation starts at the right page.
    let change: Vec<String> = domains
        .iter()
        .map(|domain| format!("https://{domain}/.well-known/change-password"))
        .collect();
    Ok(json!({"ok": true, "item": id, "domains": domains, "change_password": change}))
}

/// `POST /v1/operator/items/sites/set`: `id` and `domains`, the whole new
/// list. An empty list clears it, which a flag built from an empty string
/// could not say.
pub fn set_from_body(body: &Value) -> Result<Value> {
    let id = body
        .get("id")
        .and_then(Value::as_str)
        .context("id required: the login whose sites change")?;
    let listed = body
        .get("domains")
        .and_then(Value::as_array)
        .context("domains required: the list of hosts the login is for, empty to clear")?;
    let domains: Option<Vec<&str>> = listed.iter().map(Value::as_str).collect();
    let Some(domains) = domains else {
        bail!("domains holds a member that is not text");
    };
    set(id, bare_hosts("domains", &domains.join(","))?)
}

/// Each domain is a bare host: what `site_host` makes of it must be itself,
/// so an address, a port or upper case is refused naming the host it would
/// have meant instead of being stored in a form no site ever matches.
/// `flag` is the option that carried the list, named in the refusal.
pub(super) fn bare_hosts(flag: &str, listed: &str) -> Result<Vec<String>> {
    let mut domains = Vec::new();
    for domain in listed.split(',').map(str::trim).filter(|domain| !domain.is_empty()) {
        let host = site_host(domain);
        if host != domain || host.contains(char::is_whitespace) {
            return Err(crate::cli::args::Usage(format!(
                "--{flag} {domain} is not a bare host; name it as {host}"
            ))
            .into());
        }
        if !domains.contains(&host) {
            domains.push(host);
        }
    }
    Ok(domains)
}

fn set(id: &str, domains: Vec<String>) -> Result<Value> {
    let mut vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "set the sites of")?;
    let mut payload = vault.get_item(id)?;
    let kind = login_kind(id, &payload)?;
    let before = domains_of(&payload);
    let root = payload
        .as_object_mut()
        .with_context(|| format!("{id}'s payload is not an object"))?;
    let context = root
        .entry("context".to_string())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .with_context(|| format!("{id}'s context is not an object"))?;
    // One list is the whole answer: a single `domain` left beside it would
    // keep a site the owner just removed.
    context.remove("domain");
    context.insert("domains".to_string(), json!(domains));
    let recipients = vault.item_recipient_uids(id)?;
    let tags = {
        let entry = vault
            .doc()
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        crate::core::vault::entry_texts(id, entry, "tags")?
    };
    vault.set_item(id, &kind, &payload, &recipients, &tags)?;
    crate::runtime::audit::append("sites-set", &json!({"item": id, "domains": domains}))?;
    Ok(json!({"ok": true, "item": id, "before": before, "domains": domains}))
}

fn login_kind(id: &str, payload: &Value) -> Result<String> {
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .with_context(|| format!("{id} records no kind"))?;
    if kind != LOGIN_KIND {
        bail!("{id} is a {kind} item; only a login is offered on sites");
    }
    Ok(kind.to_string())
}

fn domains_of(payload: &Value) -> Vec<String> {
    match payload.get("context") {
        Some(context) => item_domains(context),
        None => Vec::new(),
    }
}
