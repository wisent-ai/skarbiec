// Browser native messaging host (`skarbiec browser host`). The host is a
// field-scoped client of the loopback API: installation mints exact
// `read:item#field` capabilities for the canonical login items that exist at
// that point, so the extension never receives a whole vault item.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};

use crate::core::items::{domain_matches, item_domains};
use crate::core::totp;
use crate::net::{operator::OK_LINE, serve::serve_request};

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
        .context("read browser-host grant (run `skarbiec browser install`)")?;
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

/// Which logins the popup asks for: the ones offered on the site open in the
/// tab, or every one whose name, username or sites hold the text typed.
#[derive(Clone, Copy)]
enum Select<'a> {
    Site(&'a str),
    Text(&'a str),
}

/// Login summary for the popup: ids, display name, and username only. Password
/// and TOTP remain server-side until an explicit fill request. A login the
/// grant does not reach (added since browser install) is named under
/// `unreadable` with the API's refusal instead of failing the whole list.
fn list_logins(select: Select) -> Result<Value> {
    let items = api_post("/v1/items/list", &json!({}))?;
    let Some(rows) = items.as_array() else {
        bail!("skarbiec API /v1/items/list answered no list");
    };
    let mut logins = Vec::new();
    let mut unreadable = Vec::new();
    for row in rows {
        if row.get("kind").and_then(Value::as_str) != Some("login") {
            continue;
        }
        let Some(id) = row.get("id").and_then(Value::as_str) else {
            bail!("skarbiec API /v1/items/list listed a login without an id");
        };
        let reply = match api_post("/v1/items/read", &json!({"id": id, "field": "context"})) {
            Ok(reply) => reply,
            Err(error) => {
                unreadable.push(json!({"id": id, "error": format!("{error:#}")}));
                continue;
            }
        };
        let Some(context) = reply.get("value") else {
            bail!("item {id}: the read of context answered no value");
        };
        let domains = item_domains(context);
        if let Select::Site(host) = select {
            if !domains.iter().any(|domain| domain_matches(domain, host)) {
                continue;
            }
        }
        // A login states its display name in context.display_name, as the
        // import writes it; one that states none is shown under its id.
        let name = match crate::core::items::display_name(context) {
            Some(name) => name,
            None => id,
        };
        let username = read_text(id, "username")?;
        if let Select::Text(text) = select {
            let found = |held: &str| held.to_lowercase().contains(text);
            if !(found(name)
                || found(username.as_str())
                || domains.iter().any(|domain| found(domain.as_str())))
            {
                continue;
            }
        }
        logins.push(json!({
            "id": id,
            "name": name,
            "username": username,
            "domains": domains,
        }));
    }
    Ok(json!({"ok": true, "logins": logins, "unreadable": unreadable}))
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
        Ok(seed) => match crate::core::clock::epoch_seconds() {
            Ok(now) => match totp::code(&seed, now) {
                Ok(code) => (Some(code), None),
                Err(reason) => (None, Some(format!("item {id}: totp_secret made no code: {reason}; `skarbiec totp seed {id}` says why"))),
            },
            Err(error) => (None, Some(format!("no code was computed for item {id}: {error:#}"))),
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
                Some(domain) => list_logins(Select::Site(&domain.to_lowercase())),
                None => Ok(json!({"ok": false, "error": "domain required"})),
            },
            // Every login whose name, username or sites hold the text, for a
            // site the login names under another address.
            Some("search") => match request
                .get("text")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
            {
                Some(text) => list_logins(Select::Text(&text.to_lowercase())),
                None => Ok(
                    json!({"ok": false, "error": "text required: what the login's name, username or site holds"}),
                ),
            },
            Some("fill") => match request.get("id").and_then(Value::as_str) {
                Some(id) => fill_login(id),
                None => Ok(json!({"ok": false, "error": "id required"})),
            },
            // A new login for the owner to accept: it waits sealed in the
            // donation inbox, and the host keeps nothing of it.
            Some("offer") => api_post(
                "/v1/offers",
                &json!({
                    "site": request.get("site"),
                    "username": request.get("username"),
                    "password": request.get("password"),
                }),
            ),
            Some(action) => Ok(json!({"ok": false, "error": format!("unknown action {action:?}")})),
            None => Ok(json!({"ok": false, "error": "action required"})),
        };
        match reply {
            Ok(frame) => write_frame(&frame)?,
            Err(error) => write_frame(&json!({"ok": false, "error": format!("{error:#}")}))?,
        }
    }
    Ok(())
}
