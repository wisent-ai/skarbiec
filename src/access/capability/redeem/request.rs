// One redemption, start to finish: read the request, refuse a replay, check
// the proof, spend a use, and stream the field once.

use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::net::UnixStream;

use super::proof::{item_field, verify_proof, workload_public_key};
use super::wire::{challenge_item, denied, denied_because, pending, reply};
use crate::access::capability::state::{acquire_state_lock, load_state, now_epoch, save_state};
use crate::access::capability::{
    MAX_REQUEST_BYTES, NONCE_RETENTION_SECONDS, PROOF_DOMAIN, WIRE_VERSION,
};
use crate::core::schema::exact_token;
use crate::core::{vault::Vault, vault_path};

pub(super) fn handle(stream: &mut UnixStream) -> Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?)
        .take(MAX_REQUEST_BYTES)
        .read_line(&mut line)?;
    let Ok(request) = serde_json::from_str::<Value>(line.trim_end()) else {
        return denied(stream);
    };

    let field = |name: &str| -> String {
        request
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let operation = field("operation");
    let capability_id = field("capability_id");
    let nonce = field("nonce");
    let workload_id = field("workload_id");
    let proof = field("proof");
    let authorization_id = field("authorization_id");
    if field("version") != WIRE_VERSION
        || !matches!(operation.as_str(), "redeem" | "cancel")
        || capability_id.len() != 64
        || !capability_id
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        || !exact_token(&nonce, 128)
        || !exact_token(&workload_id, 128)
        || proof.len() != 86
    {
        return denied_because(stream, "malformed request: version, operation, capability id, nonce, workload id or proof is not the shape this wire requires");
    }

    let now = now_epoch()?;
    let _state_lock = acquire_state_lock()?;
    let mut state = load_state()?;
    let Some(record) = state["capabilities"].get(&capability_id).cloned() else {
        return denied_because(stream, "no such capability");
    };
    let remaining = record
        .get("remaining_uses")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let agent = record
        .get("agent")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let resource = record
        .get("resource")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if record.get("state").and_then(Value::as_str) != Some("issued")
        || record
            .get("expires_at")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            <= now
        || remaining == 0
        || record
            .get("authorization_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            != authorization_id
    {
        return denied_because(stream, "capability is not issued, has expired, has no uses left, or its authorization id does not match");
    }

    // The nonce is refused the moment it is seen twice, before any use is spent, so a
    // captured request cannot be replayed even inside its own validity window.
    let nonce_key = format!("{capability_id}:{nonce}");
    if state["nonces"].get(&nonce_key).is_some() {
        return denied_because(stream, "nonce already seen for this capability");
    }

    let vault = Vault::open(vault_path())?;
    let Some(public_key) = workload_public_key(&vault, &agent) else {
        return denied_because(
            stream,
            &format!("no live vault token registers a workload public key for agent {agent:?}"),
        );
    };
    let mut payload = Vec::from(PROOF_DOMAIN);
    for part in [
        capability_id.as_str(),
        nonce.as_str(),
        workload_id.as_str(),
        operation.as_str(),
    ] {
        payload.extend_from_slice(part.as_bytes());
        payload.push(0);
    }
    payload.extend_from_slice(authorization_id.as_bytes());
    if !verify_proof(&public_key, &payload, &proof)? {
        return denied_because(
            stream,
            "the proof does not verify against the registered workload key",
        );
    }

    state["nonces"][&nonce_key] = json!(now);
    if let Some(nonces) = state["nonces"].as_object_mut() {
        nonces.retain(|_, seen| seen.as_u64().unwrap_or(0) + NONCE_RETENTION_SECONDS > now);
    }

    if operation == "cancel" {
        state["capabilities"][&capability_id]["state"] = json!("cancelled");
        state["capabilities"][&capability_id]["remaining_uses"] = json!(0);
        save_state(&state)?;
        crate::runtime::audit::append_sync(
            "capability-cancelled",
            &json!({"capability_id": capability_id, "agent": agent, "resource": resource}),
        )?;
        return reply(
            stream,
            json!({"version": WIRE_VERSION, "status": "ok", "secret_len": 0}),
            &[],
        );
    }

    let coordinate = match crate::access::route::resolution::coordinate_for(&resource)? {
        Ok((item, field)) => (item, field),
        Err(_) => (challenge_item(&resource), "value".to_string()),
    };
    let secret = item_field(&vault, &coordinate.0, &coordinate.1);
    let Some(secret) = secret else {
        // The route exists but nothing has written the value yet. For a challenge that
        // is the normal state between issuing and the relay storing.
        if resource.starts_with("challenge:") {
            save_state(&state)?;
            return pending(stream);
        }
        // A bare refusal here sends the caller a redemption that "was denied"
        // for a resource whose route is present and whose item opens by hand,
        // and it leaves out the only fact that separates a wrong coordinate
        // from an item this process cannot open: which coordinate was read.
        // The coordinate is configuration, not a secret.
        return denied_because(
            stream,
            &format!(
                "no value at {}#{} for resource {resource}",
                coordinate.0, coordinate.1
            ),
        );
    };

    state["capabilities"][&capability_id]["remaining_uses"] = json!(remaining - 1);
    if remaining == 1 {
        state["capabilities"][&capability_id]["state"] = json!("spent");
    }
    save_state(&state)?;
    crate::runtime::audit::append_sync(
        "capability-redeemed",
        &json!({"capability_id": capability_id, "agent": agent, "resource": resource}),
    )?;
    reply(
        stream,
        json!({"version": WIRE_VERSION, "status": "ok", "secret_len": secret.len()}),
        secret.as_bytes(),
    )
}
