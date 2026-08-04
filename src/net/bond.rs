// Bond serve channel (docs/design/bond.md): the replica-mode pull client and
// the serve handlers it talks to. `pull` fetches the whole ciphertext document
// from a serve and atomically replaces the local vault with it; `GET /v1/vault`
// is the serving side of that channel, gated by a `sync:pull` grant;
// `POST /v1/enroll` lets a replica register its key and be re-sealed into
// listed items. These live in their own module so each source file stays
// within the repository's per-file line budget.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;

use crate::access::tokens;
use crate::core::{crypto, inbox, vault_path};
use crate::net::http;

fn now_iso() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Minimal blocking HTTP client for a loopback serve: returns the status line
/// and the parsed JSON body. A non-JSON body is an error naming the status,
/// so a refused request surfaces the server's answer. Only plain http to an
/// explicit host:port — the serve listener is loopback-only by design.
pub(crate) fn serve_request(
    base: &str,
    method: &str,
    path: &str,
    consumer: &str,
    bearer: &str,
    body: Option<&Value>,
) -> Result<(String, Value)> {
    let authority = base.strip_prefix("http://").unwrap_or(base);
    let authority = authority.trim_end_matches('/');
    if authority.is_empty() || authority.contains('/') {
        bail!("base url must be http://host:port with no path: {base}");
    }
    let payload = match body {
        Some(value) => serde_json::to_string(value)?,
        None => String::new(),
    };
    let mut stream =
        TcpStream::connect(authority).with_context(|| format!("connect {authority}"))?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {bearer}\r\nX-Consumer: {consumer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream.write_all(request.as_bytes())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let (head, text) = raw
        .split_once("\r\n\r\n")
        .context("malformed HTTP response")?;
    let status = head.lines().next().unwrap_or_default().to_string();
    let parsed: Value = serde_json::from_str(text)
        .with_context(|| format!("response from {path} is not JSON (status: {status})"))?;
    Ok((status, parsed))
}

fn item_count(doc: &Value) -> usize {
    doc.get("items")
        .and_then(Value::as_object)
        .map(|items| items.len())
        .unwrap_or_default()
}

/// `GET /v1/vault` — replica-mode pull of the whole ciphertext document.
/// Requires a `sync:pull` grant; items are served exactly as stored
/// ciphertext and are never decrypted here.
pub(crate) fn handle_vault_pull(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
) -> Result<()> {
    let (consumer, bearer) = http::presented_identity(headers);
    let vault = http::load()?;
    if consumer.is_empty()
        || !tokens::token_allows_vault_action(&vault, &consumer, &bearer, "sync", "pull")?
    {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "sync:pull grant required"}),
        );
    }
    crate::runtime::audit::append("http-vault-pull", &json!({"consumer": consumer}))?;
    http::write_response(stream, "HTTP/1.1 200 OK", vault.doc())
}

/// `POST /v1/enroll` — a replica sends its armored public key and a list of
/// item ids; the source registers the key as a member recipient and re-seals
/// each listed item to include it. Requires an `enroll` grant. After the next
/// pull, the replica can open exactly those items with its own key.
pub(crate) fn handle_enroll(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let bad = "HTTP/1.1 400 Bad Request";
    let parsed = http::request_json(body);
    let Some(uid) = parsed
        .get("uid")
        .and_then(Value::as_str)
        .filter(|u| !u.is_empty())
    else {
        return http::write_response(stream, bad, &json!({"error": "uid required"}));
    };
    let Some(armored) = parsed
        .get("armored")
        .and_then(Value::as_str)
        .filter(|a| !a.is_empty())
    else {
        return http::write_response(stream, bad, &json!({"error": "armored required"}));
    };
    let items: Vec<String> = parsed
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    let (consumer, bearer) = http::presented_identity(headers);
    let mut vault = http::load()?;
    if consumer.is_empty()
        || !tokens::token_allows_vault_action(&vault, &consumer, &bearer, "enroll", "")?
    {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "enroll grant required"}),
        );
    }
    crypto::import_key(armored).context("import enrolled public key")?;
    let fingerprint =
        crypto::fingerprint_for(uid)?.context("enrolled key has no uid match in the keyring")?;
    vault.register_recipient(uid, &fingerprint, "member")?;
    let mut shared = Vec::new();
    let mut skipped = Vec::new();
    for id in &items {
        let known = vault
            .doc()
            .get("items")
            .and_then(Value::as_object)
            .is_some_and(|all| all.contains_key(id));
        if !known {
            skipped.push(id.clone());
            continue;
        }
        let payload = vault.get_item(id)?;
        let item_kind = vault
            .doc()
            .get("items")
            .and_then(|all| all.get(id))
            .and_then(|item| item.get("kind"))
            .and_then(Value::as_str)
            .context("canonical item has no kind")?
            .to_string();
        let tags: Vec<String> = vault
            .doc()
            .get("items")
            .and_then(|all| all.get(id))
            .and_then(|item| item.get("tags"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        let mut recipients = vault.item_recipient_uids(id);
        if !recipients.iter().any(|r| r == uid) {
            recipients.push(uid.to_string());
        }
        // Re-encryption preserves the active revision's provenance.
        let writer = inbox::written_by(&vault, id);
        if let Some(writer) = writer.as_deref() {
            vault.set_item_written_by(id, &item_kind, &payload, &recipients, &tags, writer)?;
        } else {
            vault.set_item(id, &item_kind, &payload, &recipients, &tags)?;
        }
        shared.push(id.clone());
    }
    crate::runtime::audit::append(
        "http-enroll",
        &json!({"consumer": consumer, "uid": uid, "shared": shared, "skipped": skipped}),
    )?;
    http::write_response(
        stream,
        "HTTP/1.1 200 OK",
        &json!({"ok": true, "uid": uid, "fingerprint": fingerprint, "shared": shared, "skipped": skipped}),
    )
}

// Replica mode: fetch the whole ciphertext document from a serve channel and
// atomically replace the local vault with it. A replica must never shrink:
// replacing the local vault with a smaller one destroys local-only items, so
// the pull refuses unless forced. The staged file sits next to the live vault
// so the rename is atomic and no reader sees a partial write. Local bond
// configs are the replica's own relationships — they are carried across the
// replace and stamped with the pull time so sync-status can report it.
pub(crate) fn cmd_pull(flags: &HashMap<String, String>) -> Result<Value> {
    let from = flags.get("from").context(
        "usage: pull --from <base-url> --token <token> [--bond name] [--consumer name] [--force]",
    )?;
    let token = flags.get("token").context("--token required")?;
    let consumer = flags
        .get("consumer")
        .map(String::as_str)
        .unwrap_or("replica");
    let (status, pulled) = serve_request(from, "GET", "/v1/vault", consumer, token, None)?;
    if pulled.get("items").and_then(Value::as_object).is_none() || pulled.get("version").is_none() {
        bail!("remote did not return a vault document (status: {status}, body: {pulled})");
    }
    let remote_count = item_count(&pulled);
    let live = vault_path();
    let local: Value = if live.exists() {
        serde_json::from_str(
            &std::fs::read_to_string(&live)
                .with_context(|| format!("read vault {}", live.display()))?,
        )?
    } else {
        json!({})
    };
    let local_count = item_count(&local);
    if remote_count < local_count && !flags.contains_key("force") {
        return Ok(json!({
            "ok": false,
            "reason": "remote_has_fewer_items",
            "items_before": local_count,
            "items_after": remote_count,
            "detail": "refusing to replace the local vault with a smaller one; re-run with --force to accept the loss"
        }));
    }
    let mut doc = pulled;
    if let Some(bonds) = local.get("bond").cloned() {
        doc["bond"] = bonds;
    }
    let stamp = now_iso();
    let wanted = flags.get("bond");
    let address = from.trim_end_matches('/');
    if let Some(bonds) = doc.get_mut("bond").and_then(Value::as_object_mut) {
        for (name, entry) in bonds.iter_mut() {
            let addressed = entry
                .get("channel")
                .and_then(|c| c.get("address"))
                .and_then(Value::as_str)
                .is_some_and(|a| a.trim_end_matches('/') == address);
            if addressed || wanted.is_some_and(|w| w == name) {
                entry["last_pull_at"] = json!(stamp);
                entry["last_items_after"] = json!(remote_count);
            }
        }
    }
    let staged = live.with_extension(format!("json.pull-{}", std::process::id()));
    std::fs::write(&staged, serde_json::to_string_pretty(&doc)?)
        .with_context(|| format!("stage pulled vault at {}", staged.display()))?;
    std::fs::rename(&staged, &live).context("install pulled vault")?;
    crate::runtime::audit::append(
        "pull",
        &json!({"from": from, "items_before": local_count, "items_after": remote_count}),
    )?;
    Ok(json!({"ok": true, "items_before": local_count, "items_after": remote_count}))
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    _positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "pull" => cmd_pull(flags).map(Some),
        _ => Ok(None),
    }
}
