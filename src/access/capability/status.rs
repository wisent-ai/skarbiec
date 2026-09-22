//! Inspect the running broker before issuing capabilities into its shared state.
//! A listening transport is not proof that any credential can be redeemed.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::absolute;

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

use super::state::{routes_path, state_path};
use super::MAX_REQUEST_BYTES;
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

pub(super) fn inspect(flags: &HashMap<String, String>) -> Result<Value> {
    let socket = flags
        .get("socket")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("SKARBIEC_CAP_SOCKET").map(Into::into))
        .unwrap_or_else(|| vault_path().with_extension("sock"));
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
        .take(MAX_REQUEST_BYTES)
        .read_line(&mut line)
        .with_context(|| format!("read capability broker status from {}", socket.display()))?;
    ensure!(
        line.ends_with('\n'),
        "capability broker {} did not return a complete bounded status response",
        socket.display()
    );
    let mut response: Value = serde_json::from_str(&line)
        .with_context(|| format!("decode capability broker status from {}", socket.display()))?;
    ensure!(
        response["version"] == VERSION
            && response["status"] == "listening"
            && response["pid"].as_u64().is_some_and(|pid| pid > 0),
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
