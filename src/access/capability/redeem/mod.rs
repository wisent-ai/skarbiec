// Serving redemptions: the socket the workloads connect to, and the modules
// that answer one request on it.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

mod proof;
mod request;
mod wire;

pub(in crate::access::capability) use wire::challenge_put;

use request::handle;
use wire::denied;

pub(super) fn serve(flags: &HashMap<String, String>) -> Result<Value> {
    let socket = flags
        .get("socket")
        .cloned()
        .or_else(|| std::env::var("SKARBIEC_CAP_SOCKET").ok())
        .context("capability-serve requires --socket or SKARBIEC_CAP_SOCKET")?;
    let path = PathBuf::from(&socket);
    if path.exists() {
        fs::remove_file(&path).context("remove the stale capability socket")?;
    }
    let listener = UnixListener::bind(&path).context("bind the capability socket")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .context("restrict the capability socket to its owner")?;
    eprintln!("skarbiec capability broker listening on {socket}");
    for incoming in listener.incoming() {
        let Ok(mut stream) = incoming else { continue };
        // One bad request must not take the broker down: a trajectory that dies
        // mid-redeem would otherwise strand every later flow on this host.
        if let Err(error) = handle(&mut stream) {
            let _ = crate::runtime::audit::append_sync(
                "capability-request-failed",
                &json!({"detail": error.to_string()}),
            );
            let _ = denied(&mut stream);
        }
    }
    Ok(json!({"status": "stopped"}))
}
