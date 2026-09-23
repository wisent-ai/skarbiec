//! One process owns the HTTP API, capability socket and every replication bond.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::net::TcpListener;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;

use super::pool::RequestPool;

mod accept;
mod predecessors;

pub(crate) use accept::survive as survive_accept;
pub(super) use predecessors::take_over as take_over_predecessors;

/// Run the one Skarbiec process. `http` holds every loopback listener it
/// answers on - its own port and the ports of the units it took over - and
/// the one request pool they share.
pub(super) fn serve(
    http: Option<(Vec<TcpListener>, RequestPool)>,
    flags: &HashMap<String, String>,
) -> Result<Value> {
    let (finished, exits) = mpsc::channel();
    let capability_socket =
        flags.contains_key("socket") || std::env::var_os("SKARBIEC_CAP_SOCKET").is_some();
    anyhow::ensure!(
        http.is_some() || capability_socket,
        "serve --no-http requires --socket or SKARBIEC_CAP_SOCKET: it would serve nothing"
    );
    if capability_socket {
        let capability = crate::access::capability::CapabilityListener::bind(flags)?;
        start("capability", finished.clone(), move || capability.serve())?;
    }
    // Replication is configured by the vault's bonds, not by this command's
    // arguments, so every host runs the same unit and a replica host needs no
    // second process. A bond added later is pulled after the next start.
    for bond in crate::bonds::pulled_bonds()? {
        start("replication", finished.clone(), move || {
            crate::bonds::run_sync(&bond)
        })?;
    }
    if let Some((listeners, requests)) = http {
        let requests = Arc::new(requests);
        for listener in listeners {
            let requests = Arc::clone(&requests);
            start("http", finished.clone(), move || {
                for incoming in listener.incoming() {
                    match incoming {
                        Ok(stream) => requests.submit(stream),
                        Err(error) => {
                            survive_accept(error).context("accept Skarbiec HTTP connection")?
                        }
                    }
                }
                Err(anyhow!("HTTP listener stopped"))
            })?;
        }
    }
    drop(finished);
    // Returning from the command ends the process and all its threads. A dead
    // component must not leave a still-listening but incomplete service behind.
    let (component, outcome) = exits.recv().context("service components disconnected")?;
    match outcome {
        Ok(report) => Err(anyhow!(
            "Skarbiec {component} component stopped unexpectedly: {report}"
        )),
        Err(error) => Err(error.context(format!("Skarbiec {component} component failed"))),
    }
}

fn start(
    name: &'static str,
    finished: Sender<(&'static str, Result<Value>)>,
    run: impl FnOnce() -> Result<Value> + Send + 'static,
) -> Result<()> {
    std::thread::Builder::new()
        .name(format!("skarbiec-{name}"))
        .spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(run)).unwrap_or_else(|panic| {
                let reason = panic
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| panic.downcast_ref::<&str>().copied())
                    .unwrap_or("non-text panic payload");
                Err(anyhow!("component panicked: {reason}"))
            });
            let _ = finished.send((name, outcome));
        })
        .with_context(|| format!("start Skarbiec {name} component"))?;
    Ok(())
}
