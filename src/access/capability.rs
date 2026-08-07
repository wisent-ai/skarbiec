// Capability broker: hand one field to one workload, once, without the workload
// ever holding a vault bearer.
//
// A capability is a promise made in advance by an operator ("this agent may read
// this resource, N times, until this instant") and redeemed later by a process
// that proves it is that agent. The proof is an Ed25519 signature over the exact
// request, so a stolen capability id is worthless without the workload key, and a
// captured request cannot be replayed: the nonce is recorded and refused twice.
//
// Why a socket rather than another CLI verb: the redeeming side is a browser
// trajectory mid-flight. It needs the secret in memory for the length of one form
// fill and must never receive a credential it could persist. A stream that yields
// exactly `secret_len` bytes and closes gives the caller nothing to keep, and gives
// us one place to spend the use count.
//
// Resources are indirect on purpose. The caller names `origin:https://…/password`,
// never an item and field, so the issuing operator -- not the workload -- decides
// which vault entry that stands for. capability-routes.json beside the vault is the
// only place the two vocabularies meet.
//
// `pending` is a first-class answer, not an error. A 2FA challenge resource is
// issued before the code exists, because the login that will need it is what causes
// Apple to send it. The redeeming side polls, the relay stores, the poll succeeds.
// Denying would force the caller to tell "not yet" from "never" by guessing.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use crate::core::{crypto, vault::Vault, vault_path};

const PROOF_DOMAIN: &[u8] = b"SKARBIEC-WORKLOAD-PROOF\0v1\0";
const WIRE_VERSION: &str = "skarbiec.redeem.v1";
const MAX_REQUEST_BYTES: u64 = 8 * 1024;
const MAX_TTL_SECONDS: u64 = 3600;
const NONCE_RETENTION_SECONDS: u64 = 2 * MAX_TTL_SECONDS;

/// Apple ships LibreSSL as `openssl`, and LibreSSL has no Ed25519 in `pkeyutl`, so on
/// a stock Mac every proof would fail verification for a reason that looks like a bad
/// signature. Prefer an OpenSSL 3 build when one is installed, and let
/// SKARBIEC_OPENSSL name it when it lives somewhere else.
fn openssl_bin() -> String {
    if let Ok(configured) = std::env::var("SKARBIEC_OPENSSL") {
        if !configured.is_empty() {
            return configured;
        }
    }
    for candidate in [
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
    ] {
        if Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "openssl".to_string()
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    _positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "capability-issue" => Ok(Some(issue(flags)?)),
        "capability-serve" => Ok(Some(serve(flags)?)),
        _ => Ok(None),
    }
}

fn state_path() -> PathBuf {
    if let Ok(path) = std::env::var("SKARBIEC_CAPABILITY_FILE") {
        return PathBuf::from(path);
    }
    let vault = vault_path();
    let name = vault
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.capabilities.json"))
        .unwrap_or_else(|| "skarbiec.vault.capabilities.json".to_string());
    vault.with_file_name(name)
}

fn routes_path() -> PathBuf {
    if let Ok(path) = std::env::var("SKARBIEC_CAPABILITY_ROUTES_FILE") {
        return PathBuf::from(path);
    }
    state_path().with_file_name("capability-routes.json")
}

fn now_epoch() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn load_state() -> Result<Value> {
    let path = state_path();
    if !path.exists() {
        return Ok(json!({"version": 1, "capabilities": {}, "nonces": {}}));
    }
    let raw = fs::read_to_string(&path).context("read capability state")?;
    let parsed: Value = serde_json::from_str(&raw).context("parse capability state")?;
    if parsed.get("capabilities").and_then(Value::as_object).is_none() {
        bail!("capability state is malformed");
    }
    Ok(parsed)
}

fn save_state(state: &Value) -> Result<()> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let staging = path.with_extension("json.staging");
    write_private_file(&staging, serde_json::to_string_pretty(state)?.as_bytes())?;
    fs::rename(&staging, &path)?;
    Ok(())
}

/// Resource vocabularies meet vault coordinates only here. A resource with no route
/// is refused rather than guessed: a wrong guess hands out a credential the operator
/// never authorised for that purpose.
fn resolve_route(resource: &str) -> Result<Option<(String, String)>> {
    let path = routes_path();
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path).context("read capability routes")?;
    let parsed: Value = serde_json::from_str(&raw).context("parse capability routes")?;
    let Some(entry) = parsed.get(resource) else {
        return Ok(None);
    };
    match (
        entry.get("item").and_then(Value::as_str),
        entry.get("field").and_then(Value::as_str),
    ) {
        (Some(item), Some(field)) => Ok(Some((item.to_string(), field.to_string()))),
        _ => bail!("capability route for {resource} must name an item and a field"),
    }
}

fn exact_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.contains('\0')
        && !value.contains('\n')
        && !value.contains('\r')
}

fn issue(flags: &HashMap<String, String>) -> Result<Value> {
    let agent = flags.get("agent").map(String::as_str).unwrap_or_default();
    let purpose = flags.get("purpose").map(String::as_str).unwrap_or_default();
    let resource = flags.get("resource").map(String::as_str).unwrap_or_default();
    let target = flags.get("target").map(String::as_str).unwrap_or_default();
    if !exact_token(agent, 128) || !exact_token(purpose, 128) || !exact_token(resource, 512) {
        bail!("capability-issue requires exact --agent, --purpose, and --resource");
    }
    if !exact_token(target, 64) {
        bail!("capability-issue requires an exact --target");
    }
    let ttl: u64 = flags
        .get("ttl")
        .map(String::as_str)
        .unwrap_or("600")
        .parse()
        .context("--ttl must be whole seconds")?;
    if ttl < 1 || ttl > MAX_TTL_SECONDS {
        bail!("--ttl must be between 1 and {MAX_TTL_SECONDS} seconds");
    }
    let max_uses: u64 = flags
        .get("max-uses")
        .map(String::as_str)
        .unwrap_or("1")
        .parse()
        .context("--max-uses must be a whole number")?;
    if max_uses < 1 || max_uses > 16 {
        bail!("--max-uses must be between 1 and 16");
    }
    let authorization_id = flags.get("authorization-id").cloned().unwrap_or_default();
    if !authorization_id.is_empty() && !exact_token(&authorization_id, 64) {
        bail!("--authorization-id must be one exact identifier");
    }
    // A capability whose resource resolves to nothing would be issued now and fail
    // only at redemption, inside a flow that has already spent its one Apple password
    // submit. Refuse at issue time. `challenge:` is the documented exception: its
    // value is written later, by the relay.
    if !resource.starts_with("challenge:") && resolve_route(resource)?.is_none() {
        bail!("no capability route maps {resource} to a vault field");
    }

    let capability_id = crypto::sha256_hex(&crypto::random_token()?)?;
    let now = now_epoch()?;
    let mut state = load_state()?;
    state["capabilities"][&capability_id] = json!({
        "agent": agent,
        "purpose": purpose,
        "resource": resource,
        "target": target,
        "authorization_id": authorization_id,
        "issued_at": now,
        "expires_at": now + ttl,
        "remaining_uses": max_uses,
        "state": "issued",
    });
    save_state(&state)?;
    Ok(json!({"capability_id": capability_id, "status": "issued"}))
}

// Liveness matches tokens::active: a consumer entry carries no state field, only an
// expiry. Checking for a "state" the vault never writes would deny every redemption
// while looking like a working guard.
fn workload_public_key(vault: &Vault, agent: &str) -> Option<String> {
    let entry = vault.doc().get("tokens").and_then(|tokens| tokens.get(agent))?;
    let live = entry
        .get("expires_at")
        .and_then(Value::as_u64)
        .is_some_and(|expires_at| now_epoch().is_ok_and(|now| now < expires_at));
    if !live {
        return None;
    }
    entry
        .get("workload_public_key")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn item_field(vault: &Vault, item: &str, field: &str) -> Option<String> {
    vault
        .get_item(item)
        .ok()?
        .get("fields")
        .and_then(|fields| fields.get(field))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    let mut normalised = value.replace('-', "+").replace('_', "/");
    while normalised.len() % 4 != 0 {
        normalised.push('=');
    }
    let mut child = Command::new(openssl_bin())
        .args(["base64", "-d", "-A"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.as_mut()?.write_all(normalised.as_bytes()).ok()?;
    let done = child.wait_with_output().ok()?;
    if !done.status.success() || done.stdout.is_empty() {
        return None;
    }
    Some(done.stdout)
}

fn verify_proof(public_key: &str, payload: &[u8], signature_b64url: &str) -> Result<bool> {
    let Some(signature) = decode_base64url(signature_b64url) else {
        return Ok(false);
    };
    let parent = state_path()
        .parent()
        .context("capability state has no parent")?
        .to_path_buf();
    fs::create_dir_all(&parent)?;
    let stem = crypto::sha256_hex(&crypto::random_token()?)?;
    let key_path = parent.join(format!(".skarbiec-cap-key-{stem}"));
    let signature_path = parent.join(format!(".skarbiec-cap-sig-{stem}"));
    let payload_path = parent.join(format!(".skarbiec-cap-payload-{stem}"));
    let result = (|| -> Result<bool> {
        write_private_file(&key_path, public_key.as_bytes())?;
        write_private_file(&signature_path, &signature)?;
        write_private_file(&payload_path, payload)?;
        let status = Command::new(openssl_bin())
            .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
            .arg(&key_path)
            .args(["-rawin", "-sigfile"])
            .arg(&signature_path)
            .arg("-in")
            .arg(&payload_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("verify capability proof with openssl")?;
        Ok(status.success())
    })();
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&signature_path);
    let _ = fs::remove_file(&payload_path);
    result
}

fn reply(stream: &mut UnixStream, control: Value, body: &[u8]) -> Result<()> {
    let mut line = serde_json::to_vec(&control)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush()?;
    Ok(())
}

fn denied(stream: &mut UnixStream) -> Result<()> {
    reply(stream, json!({"version": WIRE_VERSION, "status": "denied"}), &[])
}

fn pending(stream: &mut UnixStream) -> Result<()> {
    reply(stream, json!({"version": WIRE_VERSION, "status": "pending"}), &[])
}

fn challenge_item(resource: &str) -> String {
    format!("capability-challenge-{}", resource.replace(['/', ':'], "-"))
}

fn handle(stream: &mut UnixStream) -> Result<()> {
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
        return denied(stream);
    }

    let now = now_epoch()?;
    let mut state = load_state()?;
    let Some(record) = state["capabilities"].get(&capability_id).cloned() else {
        return denied(stream);
    };
    let remaining = record.get("remaining_uses").and_then(Value::as_u64).unwrap_or(0);
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
        || record.get("expires_at").and_then(Value::as_u64).unwrap_or(0) <= now
        || remaining == 0
        || record.get("authorization_id").and_then(Value::as_str).unwrap_or("") != authorization_id
    {
        return denied(stream);
    }

    // The nonce is refused the moment it is seen twice, before any use is spent, so a
    // captured request cannot be replayed even inside its own validity window.
    let nonce_key = format!("{capability_id}:{nonce}");
    if state["nonces"].get(&nonce_key).is_some() {
        return denied(stream);
    }

    let vault = Vault::open(vault_path())?;
    let Some(public_key) = workload_public_key(&vault, &agent) else {
        return denied(stream);
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
        return denied(stream);
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

    let secret = match resolve_route(&resource)? {
        Some((item, field)) => item_field(&vault, &item, &field),
        None => item_field(&vault, &challenge_item(&resource), "value"),
    };
    let Some(secret) = secret else {
        // The route exists but nothing has written the value yet. For a challenge that
        // is the normal state between issuing and the relay storing.
        if resource.starts_with("challenge:") {
            save_state(&state)?;
            return pending(stream);
        }
        return denied(stream);
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

fn serve(flags: &HashMap<String, String>) -> Result<Value> {
    let socket = flags
        .get("socket")
        .cloned()
        .or_else(|| std::env::var("SKARBIEC_CAP_SOCKET").ok())
        .context("capability-serve requires --socket or SKARBIEC_CAP_SOCKET")?;
    let path = PathBuf::from(&socket);
    if path.exists() {
        fs::remove_file(&path).context("remove the stale capability socket")?;
    }
    let listener = UnixListener::bind(&path).context("bind the capability socket")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .context("restrict the capability socket to its owner")?;
    eprintln!("skarbiec capability broker listening on {socket}");
    for incoming in listener.incoming() {
        let Ok(mut stream) = incoming else { continue };
        // One bad request must not take the broker down: a trajectory that dies
        // mid-redeem would otherwise strand every later flow on this host.
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
