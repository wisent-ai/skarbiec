// Access + sharing layer: cryptographic per-recipient sharing, consumer service
// identities with structured capabilities, recovery / emergency access, and admin policy. Each
// submodule matches its own commands and returns None for anything else, so
// this router simply forwards to them in turn; a real error propagates via `?`.

pub mod acquisition;
pub mod capability;
pub mod grant;
pub mod policy;
pub mod recipients;
pub mod recovery;
pub mod route;
pub mod route_coordinate;
pub mod route_declaration;
pub mod route_resolution;
pub mod route_table;
pub mod route_values;

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if let Some(v) = recipients::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = acquisition::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = capability::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = route::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = grant::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = recovery::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = policy::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    Ok(None)
}
