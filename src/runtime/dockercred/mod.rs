// The docker adapter of `skarbiec helper`: a Docker credential helper
// (https://github.com/docker/docker-credential-helpers), so `docker pull` and
// `docker push` sign in to a registry with the login the vault keeps for it —
// a token as the password — and no credential sits in ~/.docker/config.json.
// Docker runs a program named docker-credential-<helper> with get, store,
// erase or list; `skarbiec helper setup docker <registry> --link <dir>` links
// that name to this binary, and main reads the name it was started under.
// `helper answer docker get` answers the same from a shell.
//
// `get` reads the registry's address on standard input and answers
// {"ServerURL","Username","Secret"}, the login chosen as `login get` chooses
// it. A registry no login is offered on is answered with the sentence Docker
// reads as "not found", so it falls back to asking. The vault keeps its own
// values: `store` (what `docker login` calls) and `erase` are refused naming
// set, and `list` is refused, since the vault answers one registry at a
// time.

use anyhow::{bail, Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::io::{Read, Write};

use crate::cli::args::Usage;
use crate::core::{schema, vault::Vault, vault_path};

mod config;
mod import;

/// What doctor checks: the registries Docker sends here, the program it runs,
/// and the sign-ins config.json still keeps in base64.
pub(crate) use config::{plain_auths, program_on_path, registries};

/// The name Docker starts a helper called `skarbiec` under.
pub const PROGRAM: &str = "docker-credential-skarbiec";
/// The sentence the helper protocol defines for a registry the helper holds
/// nothing for; Docker matches it exactly.
const NOT_FOUND: &str = "credentials not found in native keychain";
pub(crate) const TOOL: &str = "docker";
pub(crate) const USAGE: &str = "usage: helper setup docker <registry> --link <dir> | helper import docker <id> <registry> --link <dir> [--tags <tag,...>] | helper unset docker <registry> | helper answer docker get|store|erase|list  (Docker's credential helper; Docker writes the request on stdin)";

/// setup, import and unset, the verb first.
pub(crate) fn person(
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<serde_json::Value> {
    let link = || {
        flags.get("link").ok_or_else(|| {
            Usage(format!(
                "--link <dir> names a directory on PATH where Docker finds {PROGRAM}; {USAGE}"
            ))
        })
    };
    match positionals {
        [action, registry] if action == "setup" => config::setup(registry, link()?),
        [action, id, registry] if action == "import" => {
            import::import(id, registry, link()?, flags.get("tags"))
        }
        [action, registry] if action == "unset" => config::unset(registry),
        _ => Err(Usage(USAGE.to_string()).into()),
    }
}

/// Docker's side as `helper answer docker` takes it.
pub(crate) fn answer(_flags: &HashMap<String, String>, arguments: &[String]) -> Result<()> {
    run(arguments)
}

/// The registries Docker sends here, the program it runs for them and whether
/// it still leads to a binary, and the registries config.json still keeps a
/// base64 sign-in for.
pub(crate) fn status() -> Result<serde_json::Value> {
    let (config, sent) = registries()?;
    let program = program_on_path()?;
    let present = match &program {
        Some(program) => crate::core::is_present(program, "Docker's credential helper program")?,
        None => false,
    };
    Ok(json!({
        "config": config,
        "registries": sent,
        "program": program,
        "program_exists": present,
        "plain_sign_ins": plain_auths()?,
    }))
}

/// Docker's side: one action, the request on stdin, the answer on stdout.
pub fn run(positionals: &[String]) -> Result<()> {
    let action = match positionals {
        [action] => action,
        _ => return Err(Usage(USAGE.to_string()).into()),
    };
    let mut request = String::new();
    std::io::stdin()
        .read_to_string(&mut request)
        .context("read Docker's request on stdin")?;
    match action.as_str() {
        "get" => get(request.trim()),
        "store" => bail!("the vault keeps its own values, so docker login does not store into it; `skarbiec set <id> --type login` stores the registry's token in a login offered on the registry"),
        "erase" => bail!("the vault keeps its own values, so docker logout does not erase them; `skarbiec delete <id>` removes the registry's login"),
        "list" => bail!("skarbiec answers one registry at a time through get and lists none"),
        other => Err(Usage(format!("helper answer docker has no action {other}; {USAGE}")).into()),
    }
}

fn get(server: &str) -> Result<()> {
    if server.is_empty() {
        bail!("Docker's request names no registry");
    }
    let flags = HashMap::from([("field".to_string(), "username".to_string())]);
    let chosen =
        match crate::runtime::dispatch("login", &flags, &["get".to_string(), server.to_string()]) {
            Ok(Some(chosen)) => chosen,
            Ok(None) => bail!("login get answered nothing"),
            Err(error) => {
                // Docker reads this exact sentence as "nothing here" and asks
                // elsewhere; the reason goes to standard error for the person.
                eprintln!("skarbiec: {error:#}");
                println!("{NOT_FOUND}");
                bail!("{NOT_FOUND} for {server}");
            }
        };
    let item = chosen["item"].as_str().context("login get named no item")?;
    let username = chosen["value"]
        .as_str()
        .context("login get answered no username")?;
    let payload = Vault::open(vault_path())?.get_item(item)?;
    let secret = schema::field(&payload, "password")?
        .as_str()
        .with_context(|| format!("{item}'s password is not text"))?
        .to_string();
    crate::runtime::audit::append(
        "docker-credential",
        &json!({"item": item, "registry": server}),
    )?;
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(
        &mut out,
        &json!({"ServerURL": server, "Username": username, "Secret": secret}),
    )?;
    out.flush().context("hand the credential to Docker")?;
    Ok(())
}
