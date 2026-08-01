// Browser native messaging host (`skarbiec native-host`). Speaks the
// length-prefixed JSON protocol browsers expect on stdio: a u32 little-endian
// byte count, then one JSON document. The host is a scoped CLIENT of the
// loopback HTTP API, not a vault reader: it authenticates as the
// `skarbiec-browser-host` consumer, whose grant covers only `read:login-*`,
// so a compromised extension can reach login items and nothing else, and the
// vault key material never enters the browser's process tree.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};

use crate::core::crypto;

fn api_base() -> String {
    std::env::var("SKARBIEC_URL").unwrap_or_else(|_| "http://127.0.0.1:8787".to_string())
}

fn token_file() -> String {
    std::env::var("SKARBIEC_BROWSER_TOKEN_FILE").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.stado/browser-host-skarbiec-token")
    })
}

fn consumer() -> String {
    std::env::var("SKARBIEC_BROWSER_CONSUMER")
        .unwrap_or_else(|_| "skarbiec-browser-host".to_string())
}

/// One POST against the loopback API; the reply body parsed as JSON. Raw
/// TcpStream keeps the crate's dependency posture (no HTTP client library).
fn api_post(path: &str, body: &Value) -> Result<Value> {
    let base = api_base()
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let token = std::fs::read_to_string(token_file())
        .context("read browser-host grant (run `skarbiec browser-host-install`)")?;
    let payload = serde_json::to_string(body)?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {base}\r\nX-Consumer: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        consumer(),
        token.trim(),
        payload.len(),
    );
    let mut stream = std::net::TcpStream::connect(&base)
        .context("skarbiec serve unreachable on the loopback API")?;
    stream.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let body_text = text
        .split("\r\n\r\n")
        .nth(std::iter::once(()).count())
        .unwrap_or_default();
    let value: Value = serde_json::from_str(body_text)
        .with_context(|| format!("skarbiec API returned a non-JSON reply: {text}"))?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        anyhow::bail!("skarbiec API: {error}");
    }
    Ok(value)
}

/// True when `host` is `domain` itself or a subdomain of it; a suffix match
/// alone would let `notexample.com` fill an `example.com` login.
fn domain_matches(domain: &str, host: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn item_domains(item: &Value) -> Vec<String> {
    let mut out: Vec<String> = item
        .get("domains")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if let Some(single) = item.get("domain").and_then(Value::as_str) {
        out.push(single.to_string());
    }
    out
}

/// Login summary for the popup: ids, display name, and username only — the
/// password stays server-side until an explicit fill request.
fn list_logins(host: &str) -> Result<Value> {
    let items = api_post("/v1/items/list", &json!({}))?;
    let rows = items.as_array().cloned().unwrap_or_default();
    let mut logins = Vec::new();
    for row in rows {
        let Some(id) = row.get("id").and_then(Value::as_str) else {
            continue;
        };
        let detail = api_post("/v1/items/read", &json!({"id": id}))?;
        let Some(value) = detail.get("value") else {
            continue;
        };
        if !item_domains(value)
            .iter()
            .any(|domain| domain_matches(domain, host))
        {
            continue;
        }
        logins.push(json!({
            "id": id,
            "name": value.get("name").and_then(Value::as_str).unwrap_or(id),
            "username": value.get("username").and_then(Value::as_str).unwrap_or_default(),
            "domains": item_domains(value),
        }));
    }
    Ok(json!({"ok": true, "logins": logins}))
}

/// Full credential material for one explicit fill. TOTP is computed here so
/// the secret itself never crosses the protocol.
fn fill_login(id: &str) -> Result<Value> {
    let detail = api_post("/v1/items/read", &json!({"id": id}))?;
    let value = detail.get("value").cloned().unwrap_or(Value::Null);
    let totp = value
        .get("totp_secret")
        .and_then(Value::as_str)
        .and_then(crypto::totp_code);
    Ok(json!({
        "ok": true,
        "username": value.get("username").and_then(Value::as_str).unwrap_or_default(),
        "password": value.get("password").and_then(Value::as_str).unwrap_or_default(),
        "totp": totp,
    }))
}

fn read_frame() -> Result<Option<Value>> {
    let mut prefix = [u8::MIN; std::mem::size_of::<u32>()];
    match std::io::stdin().read_exact(&mut prefix) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let length = u32::from_le_bytes(prefix) as usize;
    let mut body = vec![u8::MIN; length];
    std::io::stdin().read_exact(&mut body)?;
    Ok(Some(
        serde_json::from_slice(&body).context("native message is not JSON")?,
    ))
}

fn write_frame(value: &Value) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    let length = u32::try_from(body.len())?;
    let mut out = std::io::stdout();
    out.write_all(&length.to_le_bytes())?;
    out.write_all(&body)?;
    out.flush()?;
    Ok(())
}

/// Frame loop: one shot per request, EOF ends the process. Every error goes
/// back as a structured frame — a host that dies silently looks exactly like
/// a broken install to the extension.
pub fn run() -> Result<()> {
    while let Some(request) = read_frame()? {
        let action = request
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let reply = match action {
            "ping" => Ok(json!({"ok": true, "service": "skarbiec-native-host"})),
            "list" => match request.get("domain").and_then(Value::as_str) {
                Some(domain) => list_logins(&domain.to_lowercase()),
                None => Ok(json!({"ok": false, "error": "domain required"})),
            },
            "fill" => match request.get("id").and_then(Value::as_str) {
                Some(id) => fill_login(id),
                None => Ok(json!({"ok": false, "error": format!("unknown action {action:?}")})),
            },
            _ => Ok(json!({"ok": false, "error": format!("unknown action {action:?}")})),
        };
        match reply {
            Ok(frame) => write_frame(&frame)?,
            Err(error) => write_frame(&json!({"ok": false, "error": error.to_string()}))?,
        }
    }
    Ok(())
}
