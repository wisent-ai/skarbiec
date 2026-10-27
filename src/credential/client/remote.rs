// Running a credential operation against the canonical Skarbiec instead of
// this host: the same commands, one hop away, with the caller's own bearer.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

use stado_wait as wait;

use super::super::common::{client_identity, exact_name, purpose, resume_handles};
use super::super::directory::expectation_body;
use super::super::CREDENTIAL_OPERATIONS_PATH;
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
    // The forward file named the address; a reply that never comes names it
    // too, so the caller can tell an unreachable service from a wrong address.
    let forward = forwards_dir()?.join(CANONICAL_FORWARD);
    let what = "the canonical Skarbiec's reply";
    let mut raw = wait::blocking(wait::Kind::Network, what, &authority, || {
        let mut stream = TcpStream::connect(&authority)?;
        stream.write_all(request.as_bytes())?;
        let mut raw = Vec::new();
        (&stream).read_to_end(&mut raw)?;
        Ok::<_, std::io::Error>(raw)
    })
    .with_context(|| {
        format!(
            "canonical Skarbiec did not answer on {authority}, declared by {}; run `skarbiec credential endpoint declare <url>` to correct it",
            forward.display()
        )
    })?;
    // The reply carries credential values: bytes that are not UTF-8 are
    // refused, never replaced, so no value is read other than as it was sent.
    let decoded = std::str::from_utf8(&raw).map(str::to_owned);
    raw.fill(b'\0');
    let text = decoded.with_context(|| format!("canonical Skarbiec on {authority} replied with bytes that are not UTF-8"))?;
    let Some((head, body_text)) = text.split_once("\r\n\r\n") else {
        bail!("canonical Skarbiec on {authority} closed the connection before a complete reply");
    };
    let status_line = head.lines().next().with_context(|| {
        format!("canonical Skarbiec on {authority} replied without a status line")
    })?;
    let value: Value = serde_json::from_str(body_text)
        .with_context(|| format!("canonical Skarbiec returned a non-JSON reply: {status_line}"))?;
    if status_line.contains(" 409 ") && stale_service_directory(&value) {
        bail!(
            "{DIRECTORY_STALE}: the canonical Skarbiec reports a stale service directory; refresh the Stado forwards before retrying"
        );
    }
    if !status_line.contains(" 200 ") {
        match value.get("error").and_then(Value::as_str) {
            Some(detail) => bail!(
                "canonical Skarbiec refused the credential operation ({status_line}): {detail}"
            ),
            None => bail!(
                "canonical Skarbiec refused the credential operation ({status_line}) and named no error: {value}"
            ),
        }
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
    exact_name("credential item id", credential_id)?;
    let consumer = flags.get("consumer").context("--consumer is required")?;
    exact_name("consumer", consumer)?;
    let mut body = Map::new();
    body.insert("item".to_string(), json!(credential_id));
    body.insert("operation".to_string(), json!(operation));
    body.insert("consumer".to_string(), json!(consumer));
    if let Some(value) = flags.get("purpose") {
        body.insert("purpose".to_string(), json!(purpose(value)?));
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

pub(in crate::credential) fn remote_resume(
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<Value> {
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
    exact_name("credential item id", credential_id)?;
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

pub(in crate::credential) fn remote_status(
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<Value> {
    let allowed = ["as", "token-file"];
    let usage = "usage: credential status <item-id> --as <caller> --token-file <path>; it reads once and reports settled";
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{usage}");
    }
    let credential_id = args.first().context(usage)?;
    exact_name("credential item id", credential_id)?;
    let (caller, token) = client_identity(flags)?;
    let path = format!("{CREDENTIAL_OPERATIONS_PATH}/{credential_id}");
    let snapshot = canonical_call("GET", &path, None, &caller, &token)?;
    crate::credential::status::with_settled(snapshot)
}
