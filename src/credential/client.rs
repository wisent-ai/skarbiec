// The thin client of the canonical Skarbiec: the endpoint comes from one
// owner-controlled Stado forward file, the bearer from an owner-only file, and
// the only hop is a loopback request.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::common::{client_identity, effective_uid, exact_name, purpose, resume_handles};
use super::directory::expectation_body;
use super::{CREDENTIAL_OPERATIONS_PATH, TERMINAL_STATUSES};

// Canonical Skarbiec discovery: one Stado forward file, never an environment URL.
pub(super) const FORWARDS_DIR_ENV: &str = "STADO_FORWARDS_DIR";
pub(super) const CANONICAL_FORWARD: &str = "skarbiec.local";
pub(super) const ENDPOINT_UNRESOLVED: &str = "SKARBIEC_ENDPOINT_UNRESOLVED";
pub(super) const ENDPOINT_TLS_UNSUPPORTED: &str = "SKARBIEC_ENDPOINT_TLS_UNSUPPORTED";
pub(super) const DIRECTORY_STALE: &str = "SERVICE_DIRECTORY_STALE";
pub(super) const LOOPBACK: &str = "127.0.0.1";

pub(super) fn forwards_dir() -> Result<PathBuf> {
    if let Ok(configured) = std::env::var(FORWARDS_DIR_ENV) {
        if !configured.trim().is_empty() {
            return Ok(PathBuf::from(configured.trim()));
        }
    }
    let home = std::env::var("HOME")
        .ok()
        .filter(|home| !home.trim().is_empty())
        .with_context(|| {
            format!("{ENDPOINT_UNRESOLVED}: neither {FORWARDS_DIR_ENV} nor HOME is set")
        })?;
    Ok(Path::new(home.trim()).join(".stado").join("forwards"))
}

/// The remedy every `SKARBIEC_ENDPOINT_UNRESOLVED` carries.
///
/// A fresh installation has no forward file, so this error is the first thing
/// a new operator sees from `credential`, and until now it named a path with
/// no way to produce one - the product enforced a contract it gave nobody the
/// means to satisfy.
const ENDPOINT_REMEDY: &str = "declare it with `skarbiec credential declare-endpoint <url>`";

// The canonical Skarbiec is the only remote hop, and its address comes from
// one owner-controlled Stado forward file.
pub(super) fn canonical_endpoint() -> Result<String> {
    let path = forwards_dir()?.join(CANONICAL_FORWARD);
    let metadata = fs::symlink_metadata(&path).with_context(|| {
        format!(
            "{ENDPOINT_UNRESOLVED}: no canonical forward at {}; {ENDPOINT_REMEDY}",
            path.display()
        )
    })?;
    let group_world_write = u32::from_str_radix("022", "8".parse()?)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid()?
        || metadata.permissions().mode() & group_world_write != u32::MIN
    {
        bail!(
            "{ENDPOINT_UNRESOLVED}: {} must be an owner-owned regular file without group or world write; {ENDPOINT_REMEDY}",
            path.display()
        );
    }
    let max: usize = "256".parse()?;
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("{ENDPOINT_UNRESOLVED}: read {}", path.display()))?;
    let endpoint = raw.trim().to_string();
    if endpoint.is_empty() || endpoint.len() > max || endpoint.chars().any(char::is_control) {
        bail!(
            "{ENDPOINT_UNRESOLVED}: {} must hold exactly one bounded URL; {ENDPOINT_REMEDY}",
            path.display()
        );
    }
    Ok(endpoint)
}

/// The canonical endpoint as it stands, without writing anything.
///
/// `doctor` needs the same three facts `declare-endpoint` reports - which
/// file, which address, does it answer - and must not create a file while
/// diagnosing the absence of one.
pub(crate) fn canonical_endpoint_report() -> Result<Value> {
    let path = forwards_dir()?.join(CANONICAL_FORWARD);
    let endpoint = canonical_endpoint()?;
    let authority = endpoint_authority(&endpoint)?;
    Ok(json!({
        "forward": path.display().to_string(),
        "endpoint": endpoint,
        "authority": authority,
        "answering": TcpStream::connect(&authority).is_ok(),
    }))
}

/// Write the canonical forward file this module reads.
///
/// Nothing in this product wrote it. The reader above enforces a precise
/// contract - owner-owned, no group or world write, exactly one bounded URL -
/// and every fresh installation has no such file at all, so the first
/// `credential` call on a new machine failed with a path and no way to
/// produce it. Measured on this host: the file existed from an earlier
/// session naming port 8785, which no Skarbiec serves; the default is 8787.
///
/// The declaration is verified through `canonical_endpoint` before returning,
/// so a file this command wrote can never be one the reader rejects.
pub(super) fn declare_canonical_endpoint(endpoint: &str) -> Result<Value> {
    let endpoint = endpoint.trim();
    let directory = forwards_dir()?;
    let owner_only_directory = u32::from_str_radix("700", "8".parse()?)?;
    let owner_only_file = u32::from_str_radix("600", "8".parse()?)?;
    fs::create_dir_all(&directory)
        .with_context(|| format!("create forwards directory {}", directory.display()))?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(owner_only_directory))
        .with_context(|| format!("protect forwards directory {}", directory.display()))?;
    let path = directory.join(CANONICAL_FORWARD);
    let staging = path.with_extension("local.staging");
    fs::write(&staging, format!("{endpoint}\n"))
        .with_context(|| format!("write {}", staging.display()))?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(owner_only_file))
        .with_context(|| format!("protect {}", staging.display()))?;
    fs::rename(&staging, &path).with_context(|| format!("publish {}", path.display()))?;
    let declared = canonical_endpoint()?;
    let authority = endpoint_authority(&declared)?;
    // Whether anything answers is a separate question from whether the
    // declaration is well formed, and the report says both rather than
    // conflating them the way a bare connection error does.
    let answering = TcpStream::connect(&authority).is_ok();
    Ok(json!({
        "forward": path.display().to_string(),
        "endpoint": declared,
        "authority": authority,
        "answering": answering,
    }))
}

// https is a valid canonical endpoint but needs a TLS client this binary does
// not carry, so only a loopback forward is reachable in process.
pub(super) fn endpoint_authority(endpoint: &str) -> Result<String> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .with_context(|| format!("{ENDPOINT_UNRESOLVED}: {endpoint} is not an absolute URL"))?;
    let authority = rest.trim_end_matches('/');
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('@')
        || authority.chars().any(char::is_whitespace)
    {
        bail!("{ENDPOINT_UNRESOLVED}: {endpoint} must name one host and port and no path");
    }
    let (host, port) = authority
        .rsplit_once(':')
        .with_context(|| format!("{ENDPOINT_UNRESOLVED}: {endpoint} must name an exact port"))?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("{ENDPOINT_UNRESOLVED}: {endpoint} must name an exact numeric port");
    }
    let loopback = matches!(host, LOOPBACK | "localhost" | "[::1]");
    match scheme {
        "https" => bail!(
            "{ENDPOINT_TLS_UNSUPPORTED}: {endpoint} needs a TLS client; publish the canonical Skarbiec through a loopback Stado forward instead"
        ),
        "http" if loopback => Ok(authority.to_string()),
        _ => bail!(
            "{ENDPOINT_UNRESOLVED}: {endpoint} must be https or http on the loopback interface"
        ),
    }
}

pub(super) fn stale_service_directory(value: &Value) -> bool {
    let text = format!(
        "{} {}",
        value
            .get("error_code")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or_default()
    )
    .to_lowercase();
    text.contains("service_directory_stale")
        || (text.contains("service directory") && text.contains("stale"))
}

pub(super) fn canonical_call(
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

pub(super) fn remote_operation(
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

pub(super) fn remote_resume(flags: &HashMap<String, String>, args: &[String]) -> Result<Value> {
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

pub(super) fn remote_status(flags: &HashMap<String, String>, args: &[String]) -> Result<Value> {
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
