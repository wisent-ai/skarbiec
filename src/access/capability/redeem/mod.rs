// Serving redemptions: the socket the workloads connect to, and the modules
// that answer one request on it.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

mod proof;
mod request;
mod wire;

pub(in crate::access::capability) use wire::challenge_put;

use request::handle;
use wire::denied;

pub(crate) struct CapabilityListener {
    listener: UnixListener,
}

impl CapabilityListener {
    pub(crate) fn bind(flags: &HashMap<String, String>) -> Result<Self> {
        let socket = flags
            .get("socket")
            .cloned()
            .or_else(|| std::env::var("SKARBIEC_CAP_SOCKET").ok())
            .context("serve redeems capabilities only with --socket or SKARBIEC_CAP_SOCKET")?;
        let path = PathBuf::from(&socket);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                anyhow::ensure!(
                    metadata.file_type().is_socket(),
                    "capability socket path is not a socket: {socket}"
                );
                match UnixStream::connect(&path) {
                    Ok(_) => anyhow::bail!("capability socket is already served: {socket}"),
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        fs::remove_file(&path).context("remove the stale capability socket")?;
                    }
                    Err(error) => return Err(error).context("inspect capability socket owner"),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect capability socket path"),
        }
        let listener = UnixListener::bind(&path).context("bind the capability socket")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .context("restrict the capability socket to its owner")?;
        eprintln!("skarbiec capability broker listening on {socket}");
        Ok(Self { listener })
    }

    pub(crate) fn serve(self) -> Result<Value> {
        for incoming in self.listener.incoming() {
            let mut stream = match incoming {
                Ok(stream) => stream,
                Err(error) => {
                    crate::net::http::survive_accept(error)
                        .context("accept capability connection")?;
                    continue;
                }
            };
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
}
