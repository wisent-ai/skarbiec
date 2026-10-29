// Creating a login whose password is generated in the vault: the account
// sign-up step, where the value is made, checked against the policy and
// stored without ever reaching standard output, a shell variable or the
// clipboard. Reading it afterwards is `get --field password`, a deliberate
// second act.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::cli::args::OrUsage;
use crate::core::{schema, vault::Vault, vault_path};

const USAGE: &str = "usage: login new <id> --username <name> [--sites <domain,...>] [--name <display name>] [--tags <tag,...>] (--length <N> [--lower] [--upper] [--digits] [--symbols | --symbols-from <chars>] [--unambiguous] | --passphrase --words <N> --separator <text> [--capitalize] [--with-digit] | --rules '<password rules>')";

/// The generator reads its own options from the same flags, so a new
/// login's password is made exactly as `generate` makes one.
pub fn run(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let id = positionals.first().or_usage(USAGE)?;
    let username = flags.get("username").or_usage(USAGE)?;
    if flags.contains_key("into") {
        return Err(crate::cli::args::Usage(format!(
            "login new writes the password into the login it creates; --into is generate's, not login new's. {USAGE}"
        ))
        .into());
    }
    let domains = match flags.get("sites") {
        Some(listed) => super::sites::bare_hosts("sites", listed)?,
        None => Vec::new(),
    };
    {
        let vault = Vault::open(vault_path())?;
        if vault
            .doc()
            .get("items")
            .and_then(|items| items.get(id.as_str()))
            .is_some()
        {
            bail!("{id} already exists; login new creates an item and never replaces one (generate --into {id} --field password replaces its password)");
        }
    }
    let generated = crate::cli::generate::generate_value(flags)?;
    let password = generated
        .get("password")
        .or_else(|| generated.get("passphrase"))
        .and_then(Value::as_str)
        .context("generate answered neither a password nor a passphrase")?
        .to_string();
    let verdict = crate::access::policy::check(&password)?;
    if verdict["ok"] != json!(true) {
        bail!(
            "the generated password does not clear the vault policy ({}); nothing was created. Generate a longer one",
            verdict["rules"]
        );
    }
    let mut fields = Map::new();
    fields.insert("username".to_string(), json!(username));
    fields.insert("password".to_string(), json!(password));
    let mut context = Map::new();
    if !domains.is_empty() {
        context.insert("domains".to_string(), json!(domains));
    }
    if let Some(name) = flags.get("name") {
        context.insert(crate::core::items::DISPLAY_NAME.to_string(), json!(name));
    }
    // The site's rules the password was made by stay with the login, so the
    // next rotation follows them too (`generate --rules-of <id>`).
    if let Some(rules) = flags.get("rules") {
        context.insert(
            crate::core::items::PASSWORD_RULES.to_string(),
            json!(rules.trim()),
        );
    }
    let payload = schema::payload("login", fields, context)?;
    let mut write = HashMap::new();
    if let Some(tags) = flags.get("tags") {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "login new")?;
    let revision = Vault::open(vault_path())?.item_revision(id)?;
    crate::runtime::audit::append(
        "login-created",
        &json!({"item": id, "sites": domains, "revision": revision}),
    )?;
    // Autofill connected here offers the new login at once: its grant is
    // widened to it, bearer kept. Where that fails the login still exists,
    // and the answer says why autofill does not offer it yet.
    let autofill = match crate::browser::cover_login(id) {
        Ok(answer) => answer,
        Err(error) => json!({"covered": false, "error": format!("{error:#}")}),
    };
    Ok(json!({
        "ok": true,
        "item": id,
        "username": username,
        "sites": domains,
        "revision": revision,
        "autofill": autofill,
    }))
}
