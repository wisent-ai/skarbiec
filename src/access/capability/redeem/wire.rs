// The three answers a redemption can get, and the challenge resource a login
// is issued before its code exists.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::Write;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

use crate::access::capability::state::load_state;
use crate::access::capability::WIRE_VERSION;
use crate::core::{vault::Vault, vault_path};

pub(super) fn reply(stream: &mut UnixStream, control: Value, body: &[u8]) -> Result<()> {
    let mut line = serde_json::to_vec(&control)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush()?;
    stream.shutdown(Shutdown::Write)?;
    Ok(())
}

pub(super) fn denied(stream: &mut UnixStream) -> Result<()> {
    reply(
        stream,
        json!({"version": WIRE_VERSION, "status": "denied"}),
        &[],
    )
}

/// The same opaque refusal on the wire, and a reason in the operator's log.
///
/// A caller must not learn which check it failed -- that is how a probe maps
/// the authority. The operator running the broker has the opposite need, and
/// giving them nothing has cost real days: a gateway whose every redemption
/// was denied looked healthy, answered /health, listed models, and reported
/// only that some credential was "unavailable".
pub(super) fn denied_because(stream: &mut UnixStream, reason: &str) -> Result<()> {
    eprintln!("skarbiec: redemption denied: {reason}");
    denied(stream)
}

pub(super) fn pending(stream: &mut UnixStream) -> Result<()> {
    reply(
        stream,
        json!({"version": WIRE_VERSION, "status": "pending"}),
        &[],
    )
}

pub(super) fn challenge_item(resource: &str) -> String {
    format!("capability-challenge-{}", resource.replace(['/', ':'], "-"))
}

/// `apple-challenge-put <resource>` -- store the six digits a trusted device just
/// showed, under the resource an authorization already named.
///
/// This is the write half of the `challenge:` exception above. Issuing a capability
/// for a code that does not exist yet is deliberate: the login that will need it is
/// what causes Apple to send it, so the redeeming side polls and gets `pending`
/// until this runs. Without this command the poll never stops being pending, and the
/// deployment scripts that reach for it -- `skarbiec-remote-command.sh` allows
/// exactly this verb -- were calling something the binary did not implement.
///
/// The code arrives on stdin, never in argv: a remote command line is readable by
/// anybody with `ps`, and the argv of a shell command is not a place a
/// one-time code belongs while safer commands exist. The resource is not
/// length-checked here on purpose -- the authoritative check is that a live
/// capability already names it, and duplicating the grammar would be a second
/// opinion that can only drift from the issuing one.
pub(in crate::access::capability) fn challenge_put(positionals: &[String]) -> Result<Value> {
    let mut named = positionals.iter();
    let Some(resource) = named.next() else {
        bail!("apple-challenge-put requires exactly one resource");
    };
    if named.next().is_some() {
        bail!("apple-challenge-put requires exactly one resource");
    }
    if !resource.starts_with("challenge:") {
        bail!("apple-challenge-put only stores a challenge: resource");
    }

    // Only an authorized challenge may be written. The capability is issued by the
    // authorization step before the login runs, so its absence means nobody asked
    // for this code and nothing would ever read it.
    let state = load_state()?;
    let authorized = state["capabilities"]
        .as_object()
        .map(|entries| {
            entries
                .values()
                .any(|entry| entry["resource"].as_str() == Some(resource.as_str()))
        })
        .unwrap_or(false);
    if !authorized {
        bail!("no capability names {resource}; nothing authorized this challenge");
    }

    let mut code = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut code)
        .context("reading the challenge code from stdin")?;
    let code = code.trim().to_string();
    if code.is_empty() {
        bail!("apple-challenge-put reads the code from stdin and received nothing");
    }
    if !code.chars().all(|character| character.is_ascii_digit()) {
        bail!("an Apple challenge code is digits only");
    }

    let item = challenge_item(resource);
    let mut vault = Vault::open(vault_path())?;
    vault.set_item(
        &item,
        "note",
        &json!({
            "schema": "skarbiec.item.v2",
            "kind": "note",
            "fields": { "value": code },
        }),
        &[],
        &["challenge".to_string()],
    )?;
    vault.save()?;
    crate::runtime::audit::append_sync(
        "apple-challenge-stored",
        &json!({"resource": resource, "item": item}),
    )?;
    Ok(json!({"status": "stored", "resource": resource}))
}
