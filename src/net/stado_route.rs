//! Where a service Skarbiec calls answers for it, asked of this host's Stado
//! resolver in process: the resolver publishes the address of its resolution
//! API in its state file, and `GET /v1/resolve/service/<service>` with the
//! consumer named answers the loopback adapter this host reaches the service
//! through. No Stado program is started.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::path::PathBuf;

use super::loopback;

/// The file the running resolver publishes its state in.
const STATE_FILE: &str = "resolver-state.json";
/// Overrides where that file is, as Stado itself reads it.
const STATE_FILE_ENV: &str = "STADO_RESOLVER_STATE_FILE";

/// The remedy every refusal here ends with.
const REMEDY: &str =
    "Stado's resolver runs in `stado serve`; `stado resolver status` says whether it runs and why not";

fn state_path() -> PathBuf {
    match crate::core::env::path(STATE_FILE_ENV) {
        Some(path) => path,
        None => crate::core::home_dir().join(".stado").join(STATE_FILE),
    }
}

/// The address the resolver answers its resolution API on.
fn api_address() -> Result<std::net::SocketAddr> {
    let path = state_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => bail!(
            "no Stado resolver has published its state at {}, so no service route can be \
             asked for on this host; {REMEDY}",
            path.display()
        ),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "read the Stado resolver's state {}; give this user read permission on it",
                    path.display()
                )
            })
        }
    };
    let state: Value = serde_json::from_str(&text).with_context(|| {
        format!(
            "the Stado resolver's state {} is not JSON, so where it answers cannot be read; {REMEDY}",
            path.display()
        )
    })?;
    let Some(bind) = state.get("api_bind").and_then(Value::as_str) else {
        bail!(
            "the Stado resolver's state {} names no api_bind: that resolver (pid {}) predates \
             answering routes over its API, or has not bound it; upgrade Stado on this host and \
             restart its serve; {REMEDY}",
            path.display(),
            state
                .get("pid")
                .map_or_else(|| "unknown".to_string(), Value::to_string)
        );
    };
    loopback::loopback_authority(&format!("http://{bind}")).with_context(|| {
        format!(
            "the Stado resolver's state {} names api_bind {bind}, which is not a loopback address",
            path.display()
        )
    })
}

/// The loopback URL this host reaches `service` at, as `consumer`.
pub(crate) fn route(service: &str, consumer: &str) -> Result<String> {
    let address = api_address()?;
    let path = format!("/v1/resolve/service/{service}");
    let reply = loopback::exchange(
        address,
        "GET",
        &path,
        &[
            ("X-Stado-Consumer", consumer),
            ("Accept", "application/json"),
        ],
        None,
        "this host's Stado resolver",
    )
    .with_context(|| {
        format!(
            "the Stado resolver at {address} did not answer for {service} as {consumer}; {REMEDY}"
        )
    })?;
    let answer: Value = serde_json::from_slice(&reply.body).with_context(|| {
        format!(
            "the Stado resolver at {address} answered {} for {service} with a body that is not JSON",
            reply.status
        )
    })?;
    if reply.code != 200 {
        let said = match answer.get("error").and_then(Value::as_str) {
            Some(error) => error.to_string(),
            None => answer.to_string(),
        };
        bail!(
            "the Stado resolver refused {service} for consumer {consumer} ({}): {said}; \
             `stado service directory consumer add {service} {consumer}` declares the consumer, \
             and `stado resolver status` names a resolver that is not serving",
            reply.status
        );
    }
    match answer.get("gateway_url").and_then(Value::as_str) {
        Some(url) if !url.is_empty() => Ok(url.to_string()),
        _ => bail!(
            "the Stado resolver admits {consumer} to {service} but listens on no adapter for that \
             pair on this host ({answer}); declare one with `stado service directory consumer add \
             {service} {consumer} --target <this host>` and let the resolver publish it"
        ),
    }
}
