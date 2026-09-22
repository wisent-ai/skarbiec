//! One process owns the HTTP API, capability socket and configured replica loop.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::net::TcpListener;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{self, Sender};

use super::pool::RequestPool;

pub(super) fn serve(
    listener: TcpListener,
    requests: RequestPool,
    flags: &HashMap<String, String>,
) -> Result<Value> {
    let (finished, exits) = mpsc::channel();
    if flags.contains_key("socket") || std::env::var_os("SKARBIEC_CAP_SOCKET").is_some() {
        let capability = crate::access::capability::CapabilityListener::bind(flags)?;
        start("capability", finished.clone(), move || capability.serve())?;
    }
    if flags.contains_key("bond") {
        let flags = flags.clone();
        start("replication", finished.clone(), move || {
            crate::bonds::run_sync(&flags)
        })?;
    }
    start("http", finished, move || {
        for incoming in listener.incoming() {
            requests.submit(incoming.context("accept Skarbiec HTTP connection")?);
        }
        Err(anyhow!("HTTP listener stopped"))
    })?;
    // Returning from the command ends the process and all its threads. A dead
    // component must not leave a still-listening but incomplete service behind.
    let (component, outcome) = exits.recv().context("service components disconnected")?;
    match outcome {
        Ok(_) => Err(anyhow!("Skarbiec {component} component stopped unexpectedly")),
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
            let outcome = catch_unwind(AssertUnwindSafe(run))
                .unwrap_or_else(|_| Err(anyhow!("component panicked")));
            let _ = finished.send((name, outcome));
        })
        .with_context(|| format!("start Skarbiec {name} component"))?;
    Ok(())
}
