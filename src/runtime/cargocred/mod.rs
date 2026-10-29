// The cargo adapter of `skarbiec helper`: `helper setup|import|unset cargo`,
// and `helper answer cargo`, which Cargo runs: let `cargo publish`, `cargo
// owner` and `cargo yank` read a registry's token from the vault each time
// instead of from credentials.toml, where `cargo login` leaves it in plain
// text. setup names Cargo's own `cargo:token-from-stdout` provider running
// this binary in config.toml's [registry] global-credential-providers; Cargo
// then runs `helper answer cargo` with the registry's index URL in
// CARGO_REGISTRY_INDEX_URL, and the token printed is the password of the
// login offered on the index's host, chosen as login get chooses it, the read
// journalled. import moves one registry's token out of credentials.toml into
// a new login offered on the index host, then takes it out of the file.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io::Write;

use crate::cli::args::{OrUsage, Usage};

mod config;

pub(crate) const TOOL: &str = "cargo";
pub(crate) const USAGE: &str = "usage: helper setup cargo | helper import cargo <id> --registry <name> --host <index host> [--tags <tag,...>] | helper unset cargo | helper answer cargo  (Cargo's token-from-stdout provider, the index in CARGO_REGISTRY_INDEX_URL)";

/// setup, import and unset, the verb first.
pub(crate) fn person(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    match positionals {
        [action] if action == "setup" => config::setup(),
        [action] if action == "unset" => config::unset(),
        [action, id] if action == "import" => {
            let registry = flags.get("registry").or_usage(USAGE)?;
            let host = flags.get("host").or_usage(USAGE)?;
            import(id, registry, host, flags.get("tags"))
        }
        _ => Err(Usage(USAGE.to_string()).into()),
    }
}

/// Cargo's side: the token for the index Cargo names, on standard output.
pub(crate) fn answer(_flags: &HashMap<String, String>, arguments: &[String]) -> Result<()> {
    if !arguments.is_empty() {
        return Err(Usage(format!("helper answer cargo takes no argument; Cargo names the index in CARGO_REGISTRY_INDEX_URL. {USAGE}")).into());
    }
    get()
}

/// Whether Cargo asks this vault, and the registries credentials.toml still
/// holds a plain-text token for; doctor checks the same.
pub(crate) fn status() -> Result<Value> {
    config::status()
}

/// The host of a registry index URL as Cargo gives it — sparse+https://,
/// registry+https:// or a plain https:// address.
fn index_host(url: &str) -> Result<String> {
    let bare = match url.split_once('+') {
        Some((_, rest)) if rest.contains("://") => rest,
        _ => url,
    };
    let (_, rest) = bare
        .split_once("://")
        .with_context(|| format!("the index {url} is not an address"))?;
    let host = rest.split('/').next().context("the index names no host")?;
    Ok(crate::runtime::gitcred::checked_host(host)?.to_string())
}

fn get() -> Result<()> {
    let url = crate::core::env::text("CARGO_REGISTRY_INDEX_URL")?
        .context("Cargo named no registry index in CARGO_REGISTRY_INDEX_URL; helper answer cargo is Cargo's provider, run by Cargo")?;
    let host = index_host(&url)?;
    let flags = HashMap::from([("field".to_string(), "password".to_string())]);
    let chosen = crate::runtime::dispatch("login", &flags, &["get".to_string(), host.clone()])?
        .context("login get answered nothing")?;
    let token = chosen["value"]
        .as_str()
        .context("login get answered no password")?;
    let item = chosen["item"].as_str().context("login get named no item")?;
    crate::runtime::audit::append("cargo-credential", &json!({"item": item, "index": url}))?;
    let mut out = std::io::stdout().lock();
    writeln!(out, "{token}").context("hand the token to Cargo")?;
    out.flush().context("hand the token to Cargo")
}

fn import(id: &str, registry: &str, host: &str, tags: Option<&String>) -> Result<Value> {
    let host = crate::runtime::gitcred::checked_host(host)?;
    let (file, lines, found) = config::stored_tokens()?;
    let Some((_, at, token)) = found.into_iter().find(|(name, _, _)| name == registry) else {
        bail!(
            "{} keeps no token for registry {registry}; nothing was changed",
            file.display()
        );
    };
    let mut fields = Map::new();
    fields.insert("username".to_string(), json!(registry));
    fields.insert("password".to_string(), json!(token));
    let mut context = Map::new();
    context.insert("domains".to_string(), json!([host]));
    context.insert(
        crate::core::items::DISPLAY_NAME.to_string(),
        json!(format!("Cargo registry {registry}")),
    );
    let payload = crate::core::schema::payload("login", fields, context)?;
    let mut write = HashMap::from([("type".to_string(), "login".to_string())]);
    if let Some(tags) = tags {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "helper import cargo")?;
    let stored = crate::core::vault::Vault::open(crate::core::vault_path())?.get_item(id)?;
    if stored["fields"]["password"] != json!(token) {
        bail!(
            "{id} does not read back {registry}'s token; {} was left as it was",
            file.display()
        );
    }
    config::remove_line(&file, &lines, at).with_context(|| {
        format!(
            "{id} holds {registry}'s token, but it is still in {}",
            file.display()
        )
    })?;
    crate::runtime::audit::append(
        "cargo-credential-import",
        &json!({"item": id, "registry": registry, "host": host}),
    )?;
    let configured = config::status()?["configured"].as_bool() == Some(true);
    Ok(json!({
        "ok": true,
        "item": id,
        "registry": registry,
        "host": host,
        "file": file,
        "provider_configured": configured,
        "next": match configured {
            true => "Cargo reads the token from the vault from now on".to_string(),
            false => "`skarbiec helper setup cargo` makes Cargo read it from the vault; until then Cargo has no token for this registry".to_string(),
        },
    }))
}
