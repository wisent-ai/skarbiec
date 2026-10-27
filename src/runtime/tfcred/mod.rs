// The terraform adapter of `skarbiec helper`: a Terraform credentials helper
// (https://developer.hashicorp.com/terraform/internals/credentials-helpers),
// so `terraform init`, `plan` and `apply` read the API token of HCP Terraform,
// Terraform Enterprise or a private registry from the vault each time, and no
// token sits in credentials.tfrc.json. Terraform runs the helper program
// terraform-credentials-<name> from its plugin directory with `get|store|
// forget <host>`; `skarbiec helper setup terraform` links that name to this
// binary and names the helper in Terraform's CLI configuration, and main
// reads the name it was started under. `helper answer terraform get <host>`
// answers the same from a shell.
//
// `get <host>` answers {"token": ...}, the password of the login offered on
// the host, chosen as `login get` chooses it, and journals the read; a host no
// login is offered on is answered {}, which Terraform reads as "no token",
// with the reason on standard error. The vault keeps its own values: `store`
// (what `terraform login` calls) and `forget` (`terraform logout`) are
// refused naming the commands that do it. `helper import terraform <id>
// --host <host>` moves a token credentials.tfrc.json holds into a new login
// offered on the host, then takes it out of the file.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io::Write;

use crate::cli::args::{OrUsage, Usage};

mod config;

/// The name Terraform starts a helper called `skarbiec` under.
pub const PROGRAM: &str = "terraform-credentials-skarbiec";
pub(crate) const TOOL: &str = "terraform";
pub(crate) const USAGE: &str = "usage: helper setup terraform | helper import terraform <id> --host <host> [--tags <tag,...>] | helper unset terraform | helper answer terraform get|store|forget <host>  (Terraform's credentials helper)";

/// setup, import and unset, the verb first.
pub(crate) fn person(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    match positionals {
        [action] if action == "setup" => config::setup(),
        [action] if action == "unset" => config::unset(),
        [action, id] if action == "import" => import(id, flags.get("host").or_usage(USAGE)?, flags.get("tags")),
        _ => Err(Usage(USAGE.to_string()).into()),
    }
}

/// Terraform's side as `helper answer terraform` takes it.
pub(crate) fn answer(_flags: &HashMap<String, String>, arguments: &[String]) -> Result<()> {
    run(arguments)
}

/// Whether Terraform's configuration names this vault's helper, whether the
/// program it runs is there, and the hosts credentials.tfrc.json still holds
/// a plain-text token for; doctor checks the same.
pub(crate) fn status() -> Result<Value> {
    config::status()
}

/// Terraform's side: the action and the host as arguments, the answer on
/// standard output.
pub fn run(positionals: &[String]) -> Result<()> {
    let [action, host] = positionals else {
        return Err(Usage(USAGE.to_string()).into());
    };
    match action.as_str() {
        "get" => get(host),
        "store" => bail!(
            "the vault keeps its own values, so terraform login does not store into it; `skarbiec login new <id> --username <name> --sites {host}` or set keeps {host}'s token as a login's password"
        ),
        "forget" => bail!("the vault keeps its own values, so terraform logout does not forget them; `skarbiec delete <id>` removes {host}'s login"),
        other => Err(Usage(format!("helper answer terraform has no action {other}; {USAGE}")).into()),
    }
}

fn get(host: &str) -> Result<()> {
    let host = crate::runtime::gitcred::checked_host(host)?;
    let flags = HashMap::from([("field".to_string(), "password".to_string())]);
    let answer = match crate::runtime::dispatch("login", &flags, &["get".to_string(), host.to_string()]) {
        Ok(Some(chosen)) => {
            let token = chosen["value"].as_str().context("login get answered no password")?;
            let item = chosen["item"].as_str().context("login get named no item")?;
            crate::runtime::audit::append("terraform-credential", &json!({"item": item, "host": host}))?;
            json!({"token": token})
        }
        Ok(None) => bail!("login get answered nothing"),
        Err(error) => {
            // An empty object is "no token here" to Terraform, which then
            // goes on without one; the reason goes to the person.
            eprintln!("skarbiec: {error:#}");
            json!({})
        }
    };
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &answer)?;
    out.flush().context("hand the token to Terraform")
}

fn import(id: &str, host: &str, tags: Option<&String>) -> Result<Value> {
    let host = crate::runtime::gitcred::checked_host(host)?;
    let (file, members) = config::stored_tokens()?;
    let token = config::token_for(&members, host).with_context(|| format!("{} holds no token for {host}", file.display()))?;
    let mut fields = Map::new();
    fields.insert("username".to_string(), json!(host));
    fields.insert("password".to_string(), json!(token));
    let mut context = Map::new();
    context.insert("domains".to_string(), json!([host]));
    context.insert(crate::core::items::DISPLAY_NAME.to_string(), json!(format!("Terraform token for {host}")));
    let payload = crate::core::schema::payload("login", fields, context)?;
    let mut write = HashMap::from([("type".to_string(), "login".to_string())]);
    if let Some(tags) = tags {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "helper import terraform")?;
    let stored = crate::core::vault::Vault::open(crate::core::vault_path())?.get_item(id)?;
    if stored["fields"]["password"] != json!(token) {
        bail!("{id} does not read back {host}'s token; {} was left as it was", file.display());
    }
    config::remove_token(&file, members, host)
        .with_context(|| format!("{id} holds {host}'s token, but it is still in {}", file.display()))?;
    crate::runtime::audit::append("terraform-credential-import", &json!({"item": id, "host": host, "file": file}))?;
    let helper = config::status()?;
    Ok(json!({
        "ok": true,
        "item": id,
        "host": host,
        "file": file,
        "helper_configured": helper["configured"],
        "next": match helper["configured"].as_bool() {
            Some(true) => "Terraform reads the token from the vault from now on".to_string(),
            _ => "`skarbiec helper setup terraform` makes Terraform read it from the vault; until then Terraform has no token for this host".to_string(),
        },
    }))
}
