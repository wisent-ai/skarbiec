// The git adapter of `skarbiec helper`: a git credential helper
// (https://git-scm.com/docs/gitcredentials), so `git push` over https signs in
// with the login the vault keeps for the forge — a token as the password —
// and no credential sits in ~/.git-credentials or a keychain git manages.
// `helper setup git <host>` sets the forge's credential.helper to
// `!<this binary> helper answer git`, and git appends get, store or erase.
//
// git writes the request on standard input as key=value lines ending with a
// blank line: protocol, host, path and, when it knows one, username. For
// `get` the login is chosen as `login get` chooses it — the one the host is
// offered on, told apart by username when there are several — and the answer
// is username= and password= lines. Only https is answered: a password sent
// over plain http is refused naming why. When no login fits, the reason goes
// to standard error and the command fails, and git asks the next helper or
// the terminal, as it does for any helper that has nothing. The vault keeps
// its own values, so `store` and `erase` read git's request and change
// nothing: a password is changed with `generate --into` or set.

use anyhow::{bail, Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::io::{BufRead, Write};

use crate::cli::args::Usage;
use crate::core::{schema, vault::Vault, vault_path};

mod config;
mod import;

/// The hosts ~/.git-credentials still keeps a plain-text sign-in for; doctor
/// names those git asks this vault for.
pub(crate) use import::stored_hosts;

/// A host as git and Docker name one; the Docker helper's setup checks it too.
pub(crate) use config::checked as checked_host;
/// The forges git asks a skarbiec binary for; doctor checks each program.
pub(crate) use config::configured;

pub(crate) const TOOL: &str = "git";
pub(crate) const USAGE: &str = "usage: helper setup git <host> | helper import git <id> <host> [--username <name>] [--tags <tag,...>] | helper unset git <host> | helper answer git get|store|erase  (git's credential helper; git writes the request on stdin)";
const SECURE: &str = "https";

/// The request git wrote, key by key, up to the blank line that ends it.
fn request() -> Result<HashMap<String, String>> {
    let mut asked = HashMap::new();
    for line in std::io::stdin().lock().lines() {
        let line = line.context("read git's credential request on stdin")?;
        if line.is_empty() {
            break;
        }
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("git's request line `{line}` is not key=value"))?;
        asked.insert(key.to_string(), value.to_string());
    }
    Ok(asked)
}

/// setup, import and unset, the verb first.
pub(crate) fn person(flags: &HashMap<String, String>, positionals: &[String]) -> Result<serde_json::Value> {
    match positionals {
        [action, host] if action == "setup" => config::setup(host),
        [action, host] if action == "unset" => config::unset(host),
        [action, id, host] if action == "import" => import::import(id, host, flags.get("username"), flags.get("tags")),
        _ => Err(Usage(USAGE.to_string()).into()),
    }
}

/// git's side: one action and the request on stdin, answered in git's own
/// key=value lines.
pub(crate) fn answer(_flags: &HashMap<String, String>, arguments: &[String]) -> Result<()> {
    let [action] = arguments else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let asked = request()?;
    match action.as_str() {
        "get" => respond(&asked),
        // The vault keeps its own values; git's request is read so git is
        // never left writing to a closed pipe.
        "store" => Ok(()),
        "erase" => Ok(()),
        other => Err(Usage(format!("helper answer git has no action {other}; {USAGE}")).into()),
    }
}

/// The forges git asks this vault for, each with the program it runs and
/// whether it is still there, and the hosts ~/.git-credentials still keeps a
/// plain-text sign-in for.
pub(crate) fn status() -> Result<serde_json::Value> {
    let forges: Vec<serde_json::Value> = configured()?
        .iter()
        .map(|(host, program)| json!({"host": host, "program": program, "program_exists": program.exists()}))
        .collect();
    let stored: Vec<serde_json::Value> = stored_hosts()?.iter().map(|(file, host)| json!({"file": file, "host": host})).collect();
    Ok(json!({"forges": forges, "plain_sign_ins": stored}))
}

fn respond(asked: &HashMap<String, String>) -> Result<()> {
    let protocol = asked.get("protocol").context("git's request names no protocol")?;
    let host = asked.get("host").context("git's request names no host")?;
    if protocol != SECURE {
        bail!("git asks for a password to send over {protocol}://{host}; skarbiec answers only {SECURE}, where it is not sent in the clear");
    }
    let mut flags = HashMap::from([("field".to_string(), "username".to_string())]);
    if let Some(username) = asked.get("username") {
        flags.insert("username".to_string(), username.clone());
    }
    let site = format!("{protocol}://{host}");
    let chosen = crate::runtime::dispatch("login", &flags, &["get".to_string(), site.clone()])?
        .context("login get answered nothing")?;
    let item = chosen["item"].as_str().context("login get named no item")?;
    let username = chosen["value"].as_str().context("login get answered no username")?;
    let payload = Vault::open(vault_path())?.get_item(item)?;
    let password = schema::field(&payload, "password")?
        .as_str()
        .with_context(|| format!("{item}'s password is not text"))?
        .to_string();
    for (name, value) in [("username", username), ("password", password.as_str())] {
        if value.contains('\n') || value.contains('\0') {
            bail!("{item}'s {name} holds a line break or NUL, which git's credential protocol cannot carry");
        }
    }
    crate::runtime::audit::append("git-credential", &json!({"item": item, "site": site}))?;
    let mut out = std::io::stdout().lock();
    writeln!(out, "username={username}")?;
    writeln!(out, "password={password}")?;
    out.flush().context("hand the credential to git")?;
    Ok(())
}
