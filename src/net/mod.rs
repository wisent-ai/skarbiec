// Network layer: git-backed multi-device sync of the encrypted vault, and a
// local HTTP API the separate client products integrate against. `net::http`
// keeps the listener and the route table; `net::api` holds the handlers those
// routes call, one module per family of requests.

pub mod api;
pub mod bond;
pub mod http;
pub(crate) mod loopback;
pub mod mcp;
pub mod operator;
pub mod owner;
pub(crate) mod serve;
pub(crate) mod stado_route;
pub mod sync;

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

pub(crate) use api::access_request::handle_access_request;
pub(crate) use api::donation::handle_donation;
pub(crate) use api::identity::{handle_owner_pubkey, handle_tokens_introspect};
pub(crate) use api::items::{handle_items_put, handle_items_read, handle_items_revision};
pub(crate) use api::lifecycle::{handle_credential_operation_status, handle_credential_operations};
pub(crate) use api::offer::handle_offer;

// Shared request helpers, re-exported by net::http so handler call sites read
// the same in every module. A failure's detail reaches the caller whole: only
// the whitespace around it, which is never information, is dropped.
pub(crate) fn detail_text(detail: &str) -> String {
    detail.trim().to_owned()
}

/// The request body as JSON. A body that does not parse is answered 400
/// here, naming the parse error and the body's length; `None` tells the
/// handler that answer was written, so no handler reads a field out of a
/// body that was never JSON and reports the field as missing.
pub(crate) fn request_json(stream: &mut std::net::TcpStream, body: &str) -> Result<Option<Value>> {
    match serde_json::from_str(body) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(error) => {
            http::write_response(
                stream,
                "HTTP/1.1 400 Bad Request",
                &serde_json::json!({
                    "error": format!("the request body is not JSON ({} bytes): {error}", body.len())
                }),
            )?;
            Ok(None)
        }
    }
}

pub(crate) fn request_id(body: &Value) -> Option<&str> {
    body.get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
}

pub(crate) fn request_field(body: &Value) -> Option<&str> {
    body.get("field")
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command == "maintain" {
        return maintain(flags, positionals).map(Some);
    }
    if let Some(v) = bond::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = sync::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = http::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    Ok(None)
}

/// `skarbiec maintain`: the pass `net::http` owns (readiness proof, one pull
/// of every pulled bond), then one push of the Git mirror on
/// the host that publishes it (`mirror publish`), then revoking every timed
/// share whose end has passed on a vault that is not a replica, then letting
/// browser autofill offer every login added since it was connected, then the
/// rolling copy `backup schedule` asked for on this host, then setting again
/// every kept CI or cluster secret whose items changed (`ci keep`), then
/// every rotation policy that has fallen due (`rotation run`'s pass), so a
/// scheduled maintenance rotates keys on its own with no second trigger.
/// Every step runs; any failing fails the pass with every reason, so a
/// mirror that stopped publishing, a share that outlived its end, a login
/// autofill cannot offer, a backup disk gone, a CI secret left stale or a
/// credential that did not rotate is a failed scheduled run, not a silent one.
fn maintain(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let pass = http::dispatch("maintain", flags, positionals);
    let mirror = sync::push_if_published();
    // A host that keeps no vault has no shares to end, and a replica's shares
    // are its source's to end; its own pull replaces them.
    let path = crate::core::vault_path();
    let kept = crate::core::is_present(&path, "vault");
    let shares = match &kept {
        Ok(false) => Ok(serde_json::json!({"skipped": "this host keeps no vault"})),
        Ok(true) => match crate::core::vault::Vault::open(path) {
            Ok(vault)
                if crate::cli::items::ensure_not_replica(&vault, "shares expire").is_err() =>
            {
                Ok(
                    serde_json::json!({"skipped": "this vault is a replica; its source ends its shares"}),
                )
            }
            Ok(_) => crate::access::recipients::expire_timed_shares(),
            Err(error) => Err(error),
        },
        Err(error) => Err(anyhow::anyhow!("{error:#}")),
    };
    let autofill = match &kept {
        Ok(true) => crate::browser::autofill_maintain_pass(),
        _ => Ok(serde_json::json!({"skipped": "this host keeps no vault"})),
    };
    let backup = match &kept {
        Ok(true) => crate::runtime::backup::scheduled_pass(),
        _ => Ok(None),
    };
    let ci = match &kept {
        Ok(true) => crate::runtime::cisecrets::kept_pass(),
        _ => Ok(None),
    };
    // A replica's policies are its source's to run, and a host with no vault
    // has none; the pass says which instead of rotating.
    let rotations = crate::credential::rotation_maintain_pass();
    let shares_failed = shares
        .as_ref()
        .is_ok_and(|report| report["ok"] == serde_json::json!(false));
    let autofill_failed = autofill
        .as_ref()
        .is_ok_and(|report| report["ok"] == serde_json::json!(false));
    let ci_failed = ci.as_ref().is_ok_and(|report| {
        report
            .as_ref()
            .is_some_and(|report| report["ok"] == serde_json::json!(false))
    });
    let rotations_failed = rotations
        .as_ref()
        .is_ok_and(|report| report["ok"] == serde_json::json!(false));
    match (pass, mirror, shares, autofill, backup, ci, rotations) {
        (
            Ok(Some(mut report)),
            Ok(mirror),
            Ok(shares),
            Ok(autofill),
            Ok(backup),
            Ok(ci),
            Ok(rotations),
        ) if !shares_failed && !autofill_failed && !ci_failed && !rotations_failed => {
            report["mirror"] = serde_json::json!(mirror);
            report["shares"] = shares;
            report["autofill"] = autofill;
            report["backup"] = serde_json::json!(backup);
            report["ci_secrets"] = serde_json::json!(ci);
            report["rotations"] = rotations;
            Ok(report)
        }
        (Ok(None), _, _, _, _, _, _) => {
            anyhow::bail!("skarbiec maintain: net::http answered nothing")
        }
        (pass, mirror, shares, autofill, backup, ci, rotations) => {
            let mut reasons = Vec::new();
            if let Err(error) = pass {
                reasons.push(format!("{error:#}"));
            }
            if let Err(error) = mirror {
                reasons.push(format!("skarbiec maintain: mirror push: {error:#}"));
            }
            match shares {
                Err(error) => reasons.push(format!("skarbiec maintain: shares expire: {error:#}")),
                Ok(report) if shares_failed => reasons.push(format!(
                    "skarbiec maintain: shares expire left shares in force: {}",
                    report["failed"]
                )),
                Ok(_) => {}
            }
            match autofill {
                Err(error) => reasons.push(format!(
                    "skarbiec maintain: browser autofill cover: {error:#}"
                )),
                Ok(report) if autofill_failed => reasons.push(format!(
                    "skarbiec maintain: browser autofill could not cover: {}",
                    report["logins"]
                )),
                Ok(_) => {}
            }
            if let Err(error) = backup {
                reasons.push(format!("skarbiec maintain: scheduled backup: {error:#}"));
            }
            match ci {
                Err(error) => {
                    reasons.push(format!("skarbiec maintain: kept CI secrets: {error:#}"))
                }
                Ok(Some(report)) if ci_failed => reasons.push(format!(
                    "skarbiec maintain: kept CI secrets were not set again: {}",
                    report["failed"]
                )),
                Ok(_) => {}
            }
            match rotations {
                Err(error) => reasons.push(format!("skarbiec maintain: scheduled rotations: {error:#}")),
                Ok(report) if rotations_failed => reasons.push(format!(
                    "skarbiec maintain: {} scheduled rotation(s) were not accepted: {}; `skarbiec rotation list` names why",
                    report["failed"],
                    crate::credential::refused_rotations(&report)
                )),
                Ok(_) => {}
            }
            // A scheduled pass that fails is seen by nobody reading its log;
            // the alert this host set says so where people look.
            let failed = reasons.join("; ");
            match crate::runtime::alert::send(&format!("skarbiec maintain failed: {failed}")) {
                Ok(Some(_)) => anyhow::bail!("{failed} (the alert was posted)"),
                Ok(None) => anyhow::bail!("{failed}"),
                Err(error) => {
                    anyhow::bail!("{failed}; the alert could not be posted either: {error:#}")
                }
            }
        }
    }
}
