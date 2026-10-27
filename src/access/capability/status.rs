//! Inspect the running broker before issuing capabilities into its shared state.
//! A listening transport is not proof that any credential can be redeemed.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::absolute;

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

use super::state::{routes_path, state_path};
use crate::core::vault_path;

pub(super) const VERSION: &str = "skarbiec.capability-status.v1";

fn locations() -> Result<Value> {
    Ok(json!({
        "vault": absolute(vault_path())?,
        "capabilities": absolute(state_path())?,
        "routes": absolute(routes_path())?,
    }))
}

pub(super) fn observed() -> Result<Value> {
    Ok(json!({
        "version": VERSION,
        "status": "listening",
        "pid": std::process::id(),
        "paths": locations()?,
    }))
}

/// The running broker's status, asked on the socket it serves: the one `--socket` or
/// `SKARBIEC_CAP_SOCKET` names, as `serve` requires; no socket is guessed.
pub(super) fn inspect(flags: &HashMap<String, String>) -> Result<Value> {
    let socket = match flags.get("socket") {
        Some(socket) => socket.clone(),
        None => crate::core::env::text("SKARBIEC_CAP_SOCKET")?.context(
            "capability status asks the broker on the socket it serves: name it with --socket or SKARBIEC_CAP_SOCKET",
        )?,
    };
    let socket = absolute(socket)?;
    let mut stream = UnixStream::connect(&socket).with_context(|| {
        format!(
            "connect to shared Skarbiec capability broker {}",
            socket.display()
        )
    })?;
    serde_json::to_writer(
        &mut stream,
        &json!({"version": VERSION, "operation": "status"}),
    )?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .with_context(|| format!("read capability broker status from {}", socket.display()))?;
    ensure!(
        line.ends_with('\n'),
        "capability broker {} did not return a complete status response",
        socket.display()
    );
    let mut response: Value = serde_json::from_str(&line)
        .with_context(|| format!("decode capability broker status from {}", socket.display()))?;
    ensure!(
        response["version"] == VERSION
            && response["status"] == "listening"
            && response["pid"].as_u64().is_some(),
        "capability broker {} returned an unsupported status response: {response}",
        socket.display()
    );
    let expected = locations()?;
    ensure!(
        response["paths"] == expected,
        "capability broker {} uses different state paths: expected {expected}; observed {}",
        socket.display(),
        response["paths"]
    );
    response["socket"] = serde_json::to_value(socket)?;
    Ok(response)
}
