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

pub(in crate::access::capability) use proof::workload_public_key;
pub(in crate::access::capability) use wire::challenge_put;

use request::handle;
use wire::denied;

pub(crate) struct CapabilityListener {
    listener: UnixListener,
}

impl CapabilityListener {
    pub(crate) fn bind(flags: &HashMap<String, String>) -> Result<Self> {
        let socket = match flags.get("socket") {
            Some(socket) => socket.clone(),
            None => crate::core::env::text("SKARBIEC_CAP_SOCKET")?
                .context("serve redeems capabilities only with --socket or SKARBIEC_CAP_SOCKET")?,
        };
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
        // Owner read and write only.
        let owner_only = crate::core::mode::OWNER_READ_WRITE;
        fs::set_permissions(&path, fs::Permissions::from_mode(owner_only))
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
                // A failure that cannot be audited, or a refusal that cannot be
                // delivered, still leaves a line naming both causes.
                if let Err(audit) = crate::runtime::audit::append_sync(
                    "capability-request-failed",
                    &json!({"detail": error.to_string()}),
                ) {
                    eprintln!(
                        "skarbiec capability broker: a request failed ({error}) and the failure could not be audited: {audit}"
                    );
                }
                if let Err(answer) = denied(&mut stream) {
                    eprintln!(
                        "skarbiec capability broker: the refusal of a failed request ({error}) could not be delivered: {answer}"
                    );
                }
            }
        }
        Ok(json!({"status": "stopped"}))
    }
}
