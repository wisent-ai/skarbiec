// Browser native messaging host (`skarbiec native-host`). The host is a
// field-scoped client of the loopback API: installation mints exact
// `read:item#field` capabilities for the canonical login items that exist at
// that point, so the extension never receives a whole vault item.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};

use crate::core::totp;
use crate::net::{bond::serve_request, operator::OK_LINE};

/// The browser-host grant file: `SKARBIEC_BROWSER_TOKEN_FILE`, else under HOME.
/// An unset HOME is refused rather than read as the empty path, which would put
/// the grant under whatever directory the host was started from.
fn token_file() -> Result<std::path::PathBuf> {
    if let Some(named) = crate::core::env::path("SKARBIEC_BROWSER_TOKEN_FILE") {
        return Ok(named);
    }
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .context("HOME is not set, so the browser-host grant cannot be found")?;
    Ok(std::path::PathBuf::from(home).join(".local/state/skarbiec/browser-host-token"))
}

fn consumer() -> Result<String> {
    // Unset or blank is the host's own name; set but not text is refused, not
    // replaced.
    Ok(match crate::core::env::text("SKARBIEC_BROWSER_CONSUMER")? {
        Some(name) => name,
        None => "skarbiec-browser-host".to_string(),
    })
}

/// One POST against the loopback API through the shared serve client, so the
/// wait is announced on stderr and the reply's status is read. A refusal is an
/// error carrying the API's own words.
fn api_post(path: &str, body: &Value) -> Result<Value> {
    let base = crate::credential::canonical_authority()?;
    let token = std::fs::read_to_string(token_file()?)
        .context("read browser-host grant (run `skarbiec browser-host-install`)")?;
    let (status, value) =
        serve_request(&base, "POST", path, &consumer()?, token.trim(), Some(body))?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        bail!("skarbiec API {path}: {status}: {error}");
    }
    if status != OK_LINE {
        bail!("skarbiec API {path} answered {status}");
    }
    Ok(value)
}

/// One field of one item as the text the API answered. A value that is not
/// text is refused by name rather than read as empty, and the value itself is
/// never put into the error.
fn read_text(id: &str, field: &str) -> Result<String> {
    let reply = api_post("/v1/items/read", &json!({"id": id, "field": field}))?;
    match reply.get("value").and_then(Value::as_str) {
        Some(text) => Ok(text.to_string()),
        None => bail!("item {id}: the read of {field} answered no text value"),
    }
}

/// True when `host` is `domain` itself or a subdomain of it; a suffix match
/// alone would let `notexample.com` fill an `example.com` login.
fn domain_matches(domain: &str, host: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// The domains a login's context allows it on: its `domains` list and its
/// single `domain`. A context that states neither allows no domain.
fn item_domains(context: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(rows) = context.get("domains").and_then(Value::as_array) {
        out.extend(rows.iter().filter_map(Value::as_str).map(str::to_string));
    }
    if let Some(single) = context.get("domain").and_then(Value::as_str) {
        out.push(single.to_string());
    }
    out
}

/// Login summary for the popup: ids, display name, and username only. Password
/// and TOTP remain server-side until an explicit fill request.
fn list_logins(host: &str) -> Result<Value> {
    let items = api_post("/v1/items/list", &json!({}))?;
    let Some(rows) = items.as_array() else {
        bail!("skarbiec API /v1/items/list answered no list");
    };
    let mut logins = Vec::new();
    for row in rows {
        if row.get("kind").and_then(Value::as_str) != Some("login") {
            continue;
        }
        let Some(id) = row.get("id").and_then(Value::as_str) else {
            bail!("skarbiec API /v1/items/list listed a login without an id");
        };
        let reply = api_post("/v1/items/read", &json!({"id": id, "field": "context"}))?;
        let Some(context) = reply.get("value") else {
            bail!("item {id}: the read of context answered no value");
        };
        let domains = item_domains(context);
        if !domains.iter().any(|domain| domain_matches(domain, host)) {
            continue;
        }
        // A login states its display name in context.name; one that states
        // none is shown under its id, the only name it has.
        let name = match context.get("name").and_then(Value::as_str) {
            Some(name) => name,
            None => id,
        };
        logins.push(json!({
            "id": id,
            "name": name,
            "username": read_text(id, "username")?,
            "domains": domains,
        }));
    }
    Ok(json!({"ok": true, "logins": logins}))
}

/// Full credential material for one explicit fill. TOTP is computed here so
/// the secret itself never crosses the native-messaging protocol.
fn fill_login(id: &str) -> Result<Value> {
    let username = read_text(id, "username")?;
    let password = read_text(id, "password")?;
    // A seed is optional on a login, and installation grants its read only
    // for a login that carries one, so a refused or unusable seed is reported
    // beside the fill with its reason instead of being dropped as no factor.
    let (totp, totp_unavailable) = match read_text(id, "totp_secret") {
        Ok(seed) => match totp::code(&seed) {
            Some(code) => (Some(code), None),
            None => (
                None,
                Some(format!(
                    "item {id}: totp_secret is not a usable Base32 seed; \
                     `skarbiec totp-seed-state {id}` says why"
                )),
            ),
        },
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    Ok(json!({
        "ok": true,
        "username": username,
        "password": password,
        "totp": totp,
        "totp_unavailable": totp_unavailable,
    }))
}

fn read_frame() -> Result<Option<Value>> {
    let mut prefix = <[u8; std::mem::size_of::<u32>()]>::default();
    match std::io::stdin().read_exact(&mut prefix) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let length = u32::from_le_bytes(prefix);
    let mut body = Vec::new();
    std::io::stdin()
        .take(u64::from(length))
        .read_to_end(&mut body)?;
    if body.len() != usize::try_from(length)? {
        bail!(
            "native message ended after {} of its declared {length} bytes",
            body.len()
        );
    }
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
        let reply = match request.get("action").and_then(Value::as_str) {
            Some("ping") => Ok(json!({"ok": true, "service": "skarbiec-native-host"})),
            Some("list") => match request.get("domain").and_then(Value::as_str) {
                Some(domain) => list_logins(&domain.to_lowercase()),
                None => Ok(json!({"ok": false, "error": "domain required"})),
            },
            Some("fill") => match request.get("id").and_then(Value::as_str) {
                Some(id) => fill_login(id),
                None => Ok(json!({"ok": false, "error": "id required"})),
            },
            Some(action) => Ok(json!({"ok": false, "error": format!("unknown action {action:?}")})),
            None => Ok(json!({"ok": false, "error": "action required"})),
        };
        match reply {
            Ok(frame) => write_frame(&frame)?,
            Err(error) => write_frame(&json!({"ok": false, "error": error.to_string()}))?,
        }
    }
    Ok(())
}
