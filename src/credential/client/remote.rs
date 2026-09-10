// Running a credential operation against the canonical Skarbiec instead of
// this host: the same commands, one hop away, with the caller's own bearer.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

use std::time::{Duration, Instant};

use super::super::common::{client_identity, exact_name, purpose, resume_handles};
use super::super::directory::expectation_body;
use super::super::{CREDENTIAL_OPERATIONS_PATH, TERMINAL_STATUSES};
use super::endpoint::{
    canonical_endpoint, endpoint_authority, forwards_dir, stale_service_directory,
};
use super::{CANONICAL_FORWARD, DIRECTORY_STALE};

pub(in crate::credential) fn canonical_call(
    method: &str,
    path: &str,
    body: Option<&Value>,
    consumer: &str,
    token: &str,
) -> Result<Value> {
    let authority = endpoint_authority(&canonical_endpoint()?)?;
    let payload = match body {
        Some(value) => serde_json::to_string(value)?,
        None => String::new(),
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nX-Consumer: {consumer}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    let mut stream = TcpStream::connect(&authority).with_context(|| {
        // The address came from a file, and an operator who cannot see which
        // file cannot tell a stopped service from a stale declaration. Both
        // happened on this fleet in one evening.
        format!(
            "canonical Skarbiec is unreachable on {authority}, declared by {}; run `skarbiec credential declare-endpoint <url>` to correct it",
            forwards_dir()
                .map(|directory| directory.join(CANONICAL_FORWARD).display().to_string())
                .unwrap_or_else(|_| CANONICAL_FORWARD.to_string())
        )
    })?;
    stream.write_all(request.as_bytes())?;
    let max: u64 = "262144".parse()?;
    let mut raw = Vec::new();
    (&stream).take(max).read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    raw.fill(u8::MIN);
    let status_line = text.lines().next().unwrap_or_default().to_string();
    let body_text = text
        .split("\r\n\r\n")
        .nth(std::iter::once(()).count())
        .unwrap_or_default();
    let value: Value = serde_json::from_str(body_text)
        .with_context(|| format!("canonical Skarbiec returned a non-JSON reply: {status_line}"))?;
    if status_line.contains(" 409 ") && stale_service_directory(&value) {
        bail!(
            "{DIRECTORY_STALE}: the canonical Skarbiec reports a stale service directory; refresh the Stado forwards before retrying"
        );
    }
    if !status_line.contains(" 200 ") {
        let detail = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("no detail");
        bail!("canonical Skarbiec refused the credential operation ({status_line}): {detail}");
    }
    Ok(value)
}

pub(in crate::credential) fn remote_operation(
    operation: &str,
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<Value> {
    let allowed = [
        "consumer",
        "purpose",
        "expect-tenant",
        "expect-object-id",
        "expect-upn",
        "signup-origin",
        "as",
        "token-file",
    ];
    let usage = format!(
        "usage: credential {operation} <item-id> --consumer <consumer> [--purpose <purpose>] [--signup-origin https://<host>] [--expect-tenant <uuid>] [--expect-object-id <uuid>] [--expect-upn <email>] --as <caller> --token-file <path>"
    );
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{usage}");
    }
    let credential_id = args.first().context(usage.clone())?;
    exact_name("credential item id", credential_id, "200".parse()?)?;
    let consumer = flags.get("consumer").context("--consumer is required")?;
    exact_name("consumer", consumer, "200".parse()?)?;
    let mut body = Map::new();
    body.insert("item".to_string(), json!(credential_id));
    body.insert("operation".to_string(), json!(operation));
    body.insert("consumer".to_string(), json!(consumer));
    if flags.contains_key("purpose") {
        body.insert(
            "purpose".to_string(),
            json!(purpose(flags.get("purpose"), consumer)?),
        );
    }
    // The signup origin is the caller's declaration of where the account this
    // acquisition registers is signed up; the canonical Skarbiec checks its
    // shape and records it.
    if let Some(origin) = flags.get("signup-origin") {
        body.insert("signup_origin".to_string(), json!(origin));
    }
    if let Some(expect) = expectation_body(flags)? {
        body.insert("expect".to_string(), expect);
    }
    let (caller, token) = client_identity(flags)?;
    canonical_call(
        "POST",
        CREDENTIAL_OPERATIONS_PATH,
        Some(&Value::Object(body)),
        &caller,
        &token,
    )
}

pub(in crate::credential) fn remote_resume(flags: &HashMap<String, String>, args: &[String]) -> Result<Value> {
    let allowed = [
        "approval",
        "resume-token",
        "resume-token-file",
        "consumer",
        "operation",
        "as",
        "token-file",
    ];
    let usage = "usage: credential resume <item-id> --approval <id> --resume-token <token> --as <caller> --token-file <path>";
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{usage}");
    }
    let credential_id = args.first().context(usage)?;
    exact_name("credential item id", credential_id, "200".parse()?)?;
    let (approval_id, resume_token) = resume_handles(flags)?;
    let mut body = Map::new();
    body.insert("item".to_string(), json!(credential_id));
    body.insert("approval".to_string(), json!(approval_id));
    body.insert("resume_token".to_string(), json!(resume_token));
    if let Some(operation) = flags.get("operation") {
        body.insert("operation".to_string(), json!(operation));
    }
    if let Some(consumer) = flags.get("consumer") {
        body.insert("consumer".to_string(), json!(consumer));
    }
    let (caller, token) = client_identity(flags)?;
    canonical_call(
        "POST",
        CREDENTIAL_OPERATIONS_PATH,
        Some(&Value::Object(body)),
        &caller,
        &token,
    )
}

pub(in crate::credential) fn remote_status(flags: &HashMap<String, String>, args: &[String]) -> Result<Value> {
    let allowed = ["as", "token-file", "follow"];
    let usage = "usage: credential status <item-id> [--follow] --as <caller> --token-file <path>";
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{usage}");
    }
    let credential_id = args.first().context(usage)?;
    exact_name("credential item id", credential_id, "200".parse()?)?;
    let (caller, token) = client_identity(flags)?;
    let path = format!("{CREDENTIAL_OPERATIONS_PATH}/{credential_id}");
    if !flags.get("follow").is_some_and(|value| value == "true") {
        return canonical_call("GET", &path, None, &caller, &token);
    }
    // The canonical Skarbiec owns the poll; following it is exactly the same
    // call repeated until the operation leaves `pending`.
    let interval = Duration::from_secs("5".parse()?);
    let limit = Duration::from_secs("1800".parse()?);
    let started = Instant::now();
    loop {
        let snapshot = canonical_call("GET", &path, None, &caller, &token)?;
        let current = snapshot
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if current != "pending" {
            let mut settled = snapshot;
            settled
                .as_object_mut()
                .context("credential status is not an object")?
                .insert(
                    "follow_settled".to_string(),
                    Value::Bool(TERMINAL_STATUSES.contains(&current.as_str())),
                );
            return Ok(settled);
        }
        if started.elapsed().saturating_add(interval) > limit {
            let mut timed_out = snapshot;
            timed_out
                .as_object_mut()
                .context("credential status is not an object")?
                .insert("follow_timed_out".to_string(), Value::Bool(true));
            return Ok(timed_out);
        }
        std::thread::sleep(interval);
    }
}
