// One redemption, start to finish: read the request, refuse a replay, check
// the proof, spend a use, and stream the field once.

use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;

use super::proof::{item_field, verify_proof, workload_public_key};
use super::wire::{challenge_item, denied, denied_because, pending, reply};
use crate::access::capability::state::{acquire_state_lock, load_state, now_epoch, save_entry};
use crate::access::capability::{PROOF_DOMAIN, WIRE_VERSION};
use crate::core::schema::exact_token;
use crate::core::{vault::Vault, vault_path};

/// A capability id is the hexadecimal SHA-256 digest `grant capability` mints:
/// 256 bits, two hex digits per byte.
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
const CAPABILITY_ID_LENGTH: usize = 64;
/// A proof is an Edwards-curve signature of 64 bytes
/// (https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6) in unpadded base64url
/// (https://www.rfc-editor.org/rfc/rfc4648#section-5).
const PROOF_LENGTH: usize = 86;
/// A redemption spends one of the capability's `--max-uses`.
/// https://skarbiec.wisent.com/docs/cli/grant/capability
const ONE_USE: u64 = 1;
/// The resources whose value a device writes with `capability challenge` after the
/// capability is issued, into the resource's challenge item; every other
/// resource is read through its route.
const CHALLENGE_PREFIX: &str = "challenge:";
const MALFORMED: &str = "malformed request: version, operation, capability id, nonce, workload id, proof or authorization id is not the shape this wire requires";

/// The text value of `name` in `object`, none when it is absent or not text.
fn text<'a>(object: &'a Value, name: &str) -> Option<&'a str> {
    object.get(name).and_then(Value::as_str)
}

/// A stored capability record's field, or the sentence that names the damage:
/// a record without it is broken state, never read as an empty value.
fn recorded<'a, T>(
    record: &'a Value,
    capability_id: &str,
    name: &str,
    read: impl Fn(&'a Value) -> Option<T>,
) -> std::result::Result<T, String> {
    record.get(name).and_then(read).ok_or_else(|| {
        format!("capability {capability_id} is damaged state: its record has no valid {name}")
    })
}

pub(super) fn handle(stream: &mut UnixStream) -> Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    let Ok(request) = serde_json::from_str::<Value>(line.trim_end()) else {
        return denied(stream);
    };
    if request["version"] == super::super::status::VERSION && request["operation"] == "status" {
        return reply(stream, super::super::status::observed()?, &[]);
    }

    let (
        Some(version),
        Some(operation),
        Some(capability_id),
        Some(nonce),
        Some(workload_id),
        Some(proof),
    ) = (
        text(&request, "version"),
        text(&request, "operation"),
        text(&request, "capability_id"),
        text(&request, "nonce"),
        text(&request, "workload_id"),
        text(&request, "proof"),
    )
    else {
        return denied_because(stream, MALFORMED);
    };
    // The wire leaves authorization_id out for a capability issued without
    // one (`grant capability` without --authorization-id records "").
    let authorization_id = match request.get("authorization_id") {
        None => "",
        Some(Value::String(given)) => given.as_str(),
        Some(_) => return denied_because(stream, MALFORMED),
    };
    let cancel = match operation {
        "redeem" => false,
        "cancel" => true,
        _ => return denied_because(stream, MALFORMED),
    };
    if version != WIRE_VERSION
        || capability_id.len() != CAPABILITY_ID_LENGTH
        || !capability_id
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        || !exact_token(nonce)
        || !exact_token(workload_id)
        || proof.len() != PROOF_LENGTH
    {
        return denied_because(stream, MALFORMED);
    }

    let now = now_epoch()?;
    let _state_lock = acquire_state_lock()?;
    let mut state = load_state()?;
    let Some(record) = state["capabilities"].get(capability_id).cloned() else {
        return denied_because(stream, "no such capability");
    };
    let fields = (
        recorded(&record, capability_id, "state", Value::as_str),
        recorded(&record, capability_id, "remaining_uses", Value::as_u64),
        recorded(&record, capability_id, "expires_at", Value::as_u64),
        recorded(&record, capability_id, "authorization_id", Value::as_str),
        recorded(&record, capability_id, "agent", Value::as_str),
        recorded(&record, capability_id, "resource", Value::as_str),
    );
    let (record_state, remaining, expires_at, granted_authorization, agent, resource) = match fields
    {
        (Ok(a), Ok(b), Ok(c), Ok(d), Ok(e), Ok(f)) => (a, b, c, d, e.to_string(), f.to_string()),
        (Err(damage), ..)
        | (_, Err(damage), ..)
        | (_, _, Err(damage), ..)
        | (_, _, _, Err(damage), ..)
        | (_, _, _, _, Err(damage), _)
        | (.., Err(damage)) => return denied_because(stream, &damage),
    };
    if record_state != "issued"
        || expires_at <= now
        || remaining < ONE_USE
        || granted_authorization != authorization_id
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
    for part in [capability_id, nonce, workload_id, operation] {
        payload.extend_from_slice(part.as_bytes());
        payload.push(b'\0');
    }
    payload.extend_from_slice(authorization_id.as_bytes());
    if !verify_proof(&public_key, &payload, proof)? {
        return denied_because(
            stream,
            "the proof does not verify against the registered workload key",
        );
    }

    state["nonces"][&nonce_key] = json!(now);

    if cancel {
        // The cancelled state is what refuses every later redemption; the
        // record keeps the uses it had left when it was cancelled.
        state["capabilities"][capability_id]["state"] = json!("cancelled");
        save_entry(&state, capability_id, Some(&nonce_key))?;
        crate::runtime::audit::append_sync(
            "capability-cancelled",
            &json!({"capability_id": capability_id, "agent": agent, "resource": resource}),
        )?;
        let nothing: &[u8] = &[];
        return reply(
            stream,
            json!({"version": WIRE_VERSION, "status": "ok", "secret_len": nothing.len()}),
            nothing,
        );
    }

    // A challenge resource is read from the item `capability challenge` writes; any
    // other resource through exactly one route, and a resource the route
    // table cannot resolve is refused with the table's own sentence, never
    // read from an item nobody writes.
    let challenge = resource.starts_with(CHALLENGE_PREFIX);
    let (item, field) = if challenge {
        (challenge_item(&resource), "value".to_string())
    } else {
        match crate::access::route::resolution::coordinate_for(&resource)? {
            Ok(coordinate) => coordinate,
            Err(refusal) => {
                return denied_because(stream, &format!("resource {resource}: {refusal}"));
            }
        }
    };
    // An item that exists but cannot be opened is its own denial, with the
    // cause; only an absent item or field is "nothing written yet".
    let secret = match item_field(&vault, &item, &field) {
        Ok(secret) => secret,
        Err(error) => {
            return denied_because(
                stream,
                &format!("cannot read {item}#{field} for resource {resource}: {error:#}"),
            );
        }
    };
    let Some(secret) = secret else {
        // Nothing has written the value yet. For a challenge that is the
        // normal state between issuing and the relay storing.
        if challenge {
            save_entry(&state, capability_id, Some(&nonce_key))?;
            return pending(stream);
        }
        // A bare refusal here sends the caller a redemption that "was denied"
        // for a resource whose route is present and whose item opens by hand,
        // and it leaves out the only fact that separates a wrong coordinate
        // from an item this process cannot open: which coordinate was read.
        // The coordinate is configuration, not a secret.
        return denied_because(
            stream,
            &format!("no value at {item}#{field} for resource {resource}"),
        );
    };

    let left = remaining - ONE_USE;
    state["capabilities"][capability_id]["remaining_uses"] = json!(left);
    if left < ONE_USE {
        state["capabilities"][capability_id]["state"] = json!("spent");
    }
    save_entry(&state, capability_id, Some(&nonce_key))?;
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
