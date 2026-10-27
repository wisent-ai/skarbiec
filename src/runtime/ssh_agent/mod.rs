// Loading an SSH private key from the vault into the running ssh-agent
// without the key touching a disk: the key travels from the decrypted item
// through a pipe into `ssh-add -`, the agent holds it, and nothing stays
// behind. `--lifetime` is handed to ssh-add's own `-t`, so the agent forgets
// the key by itself.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};

use crate::core::{schema, vault::Vault, vault_path};

mod rotation;
/// rotate --with ssh swaps the retired key for the new one in the running agent.
pub(in crate::runtime) use rotation::follow_rotation;

/// The field of a key-pair item that holds the private key.
const PRIVATE_KEY_FIELD: &str = "private_key";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    const USAGE: &str = "usage: ssh add <item-id> | ssh add --tag <tag>  [--lifetime <seconds>] [--agent <socket>]";
    let Some(rest) = crate::cli::args::verb(command, positionals, "ssh", "add") else {
        return Ok(None);
    };
    match (rest, flags.get("tag")) {
        ([id], None) => add(id, flags.get("lifetime"), flags.get("agent")).map(Some),
        ([], Some(tag)) => add_tagged(tag, flags.get("lifetime"), flags.get("agent")).map(Some),
        _ => Err(crate::cli::args::Usage(USAGE.to_string()).into()),
    }
}

/// `skarbiec ssh add --tag <tag>`: every live item carrying the tag that
/// holds a private key, loaded one by one, so a day's keys — a client's
/// servers, a deploy set — go into the agent at once. One key the agent
/// refuses is named with its reason and the others still load; the answer
/// is ok only when every one did.
fn add_tagged(tag: &str, lifetime: Option<&String>, agent: Option<&String>) -> Result<Value> {
    let tagged = crate::cli::bulk::carrying(&Vault::open(vault_path())?, tag, false);
    if tagged.is_empty() {
        bail!("no live item carries the tag {tag}, so no key was added");
    }
    let mut added = Vec::new();
    let mut refused = Vec::new();
    for id in &tagged {
        match add(id, lifetime, agent) {
            Ok(answer) => added.push(answer),
            Err(error) => refused.push(json!({"item": id, "error": format!("{error:#}")})),
        }
    }
    Ok(json!({"ok": refused.is_empty(), "tag": tag, "added": added, "refused": refused}))
}

/// `skarbiec ssh add <id> [--lifetime <seconds>] [--agent <socket>]`.
///
/// `--agent` names the agent's socket; without it SSH_AUTH_SOCK does, as for
/// ssh-add itself. With neither the command is refused naming both rather
/// than letting ssh-add fail with "Could not open a connection to your
/// authentication agent". The desktop passes its own session's socket,
/// because the serving process may hold none. A key stored with a passphrase
/// is asked for by ssh-add on the terminal.
fn add(id: &str, lifetime: Option<&String>, agent: Option<&String>) -> Result<Value> {
    if let Some(lifetime) = lifetime {
        if lifetime.parse::<u64>().is_err() {
            return Err(crate::cli::args::Usage(format!(
                "--lifetime {lifetime} is not a whole number of seconds"
            ))
            .into());
        }
    }
    let socket = match agent {
        Some(agent) => std::path::PathBuf::from(agent),
        None => crate::core::env::path("SSH_AUTH_SOCK").context(
            "neither --agent nor SSH_AUTH_SOCK names an ssh-agent socket, so there is no agent to hand the key to; start one with `eval $(ssh-agent)` or use the one your session provides",
        )?,
    };
    let vault = Vault::open(vault_path())?;
    let payload = vault.get_item(id)?;
    let fields = schema::fields(&payload)?;
    let key = fields
        .get(PRIVATE_KEY_FIELD)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .with_context(|| format!("{id} holds no {PRIVATE_KEY_FIELD} text, so there is no key to add"))?;
    let mut command = Command::new("ssh-add");
    if let Some(lifetime) = lifetime {
        command.args(["-t", lifetime.as_str()]);
    }
    let mut child = command
        .arg("-")
        .env("SSH_AUTH_SOCK", &socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start ssh-add, which hands the key to the agent")?;
    // ssh-add parses a key only once it has all of it: the trailing newline
    // a PEM block ends with is written if the stored text lacks it.
    let mut text = key.to_string();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    child
        .stdin
        .take()
        .context("ssh-add was started without a standard input")?
        .write_all(text.as_bytes())
        .context("hand the private key to ssh-add")?;
    let output = stado_wait::blocking(
        stado_wait::Kind::Process,
        "ssh-add loading one vault key into the agent",
        socket.display(),
        || child.wait_with_output(),
    )
    .context("wait for ssh-add")?;
    if !output.status.success() {
        bail!(
            "ssh-add refused the key of {id} ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    crate::runtime::audit::append(
        "ssh-add",
        &json!({"item": id, "lifetime_seconds": lifetime}),
    )?;
    Ok(json!({
        "ok": true,
        "item": id,
        "agent": socket,
        "lifetime_seconds": lifetime,
        "ssh_add": String::from_utf8_lossy(&output.stderr).trim(),
    }))
}
