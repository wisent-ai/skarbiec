// Runtime layer: tamper-evident audit log, and one-time-code / breach /
// secret health / certificate expiry helpers. Each submodule matches its own
// commands and returns None otherwise; a real error propagates via `?`.
// Credential resolution moved to `access::route`, where the declaration that
// decides it lives.

pub mod age;
pub mod audit;
mod authenticator;
pub mod backup;
pub mod breach;
mod certificates;
pub mod doctor;
pub mod exec;
// The adapters `skarbiec helper` lets a tool read its credentials through.
pub mod cisecrets;
pub mod dockercred;
mod envimport;
mod exposure;
mod githook;
mod lockdown;
mod retired;
mod scan;
mod tokenexpiry;
// The providers `rotate --with <provider>` replaces a secret through.
pub(crate) mod apicall;
pub(crate) mod awscred;
mod awsrotate;
mod azrotate;
pub mod cargocred;
mod cloudflarerotate;
mod dbrotate;
pub mod expiry;
mod files;
mod gcprotate;
pub mod gitcred;
mod gitlabrotate;
pub(crate) mod gitsign;
pub mod helper;
pub(crate) mod kubecred;
pub(crate) mod revise;
pub(crate) mod rotate;
mod sendgridrotate;
pub mod tfcred;
mod twiliorotate;
mod vercelrotate;
pub(crate) mod wiring;
// The adapters `skarbiec tool` moves developer tools' tokens through.
pub(crate) mod alert;
pub(crate) mod bindings;
pub(crate) mod flycred;
pub(crate) mod gemcred;
pub(crate) mod ghcred;
mod health;
pub(crate) mod hfcred;
mod inject;
mod keygen;
mod keys;
pub mod kit;
pub mod logins;
pub mod notes;
pub(crate) mod npmcred;
mod opensite;
pub mod pins;
pub(crate) mod pypicred;
mod review;
mod rules;
mod search;
pub mod send;
mod sitebreaches;
mod ssh_agent;
pub(crate) mod tooltoken;
pub mod totp;
pub mod vaults;
pub(crate) mod vercelcred;

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if let Some(v) = audit::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = totp::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = totp::recovery_code_dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = breach::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = certificates::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = ssh_agent::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = review::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = logins::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = search::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = files::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = notes::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = keys::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = expiry::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = send::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = kit::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = age::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = pins::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = authenticator::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = backup::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = keygen::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = rules::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = sitebreaches::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = inject::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = opensite::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = envimport::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = scan::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = githook::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = cisecrets::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = lockdown::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = exposure::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = rotate::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = tooltoken::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = bindings::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = helper::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = alert::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = gitsign::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    health::dispatch(command, flags, positionals)
}
