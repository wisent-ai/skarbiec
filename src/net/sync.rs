// Git-backed multi-device sync. The vault file is ciphertext, so it is safe to
// commit and push to a remote and pull back on another device. A dedicated sync
// directory (a git repo) holds a copy named vault.enc.json; push copies the
// live vault into it and commits+pushes, pull fetches and copies it back.
//
// A pull replaces the whole live vault, so it can destroy items that exist only
// locally (created after the last push). `sync-pull` therefore snapshots the
// live vault first and refuses to proceed when local-only items would be lost,
// unless `--force` is given. Merging is deliberately not attempted: mirror and
// live vault may be encrypted to different recipient sets.
//
// This module also carries the bond serve channel (docs/design/bond.md): the
// `pull` command (replica mode over serve) with its blocking HTTP client, and
// the `GET /v1/vault` handler it pulls from. They live here because net::http
// is at the repository's per-file line budget.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;

use crate::access::tokens;
use crate::core::vault_path;
use crate::net::http;

fn sync_dir() -> PathBuf {
    if let Ok(d) = std::env::var("SKARBIEC_SYNC_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".skarbiec-sync")
}

fn mirror_path() -> PathBuf {
    sync_dir().join("vault.enc.json")
}

fn now_stamp() -> String {
    Command::new("date")
        .args(["-u", "+%Y%m%dT%H%M%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Names of live items the mirror does not carry at all. Soft-deleted items are
/// ignored: losing a tombstone is not data loss.
fn items_missing_from_mirror(live: &PathBuf, mirror: &PathBuf) -> Result<Vec<String>> {
    let read = |path: &PathBuf| -> Result<Value> {
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("read vault {}", path.display()))?;
        serde_json::from_str(&body).with_context(|| format!("parse vault {}", path.display()))
    };
    let live = read(live)?;
    let mirror = read(mirror)?;
    let mirror_items = mirror.get("items").and_then(Value::as_object);
    let Some(live_items) = live.get("items").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    let mut missing: Vec<String> = live_items
        .iter()
        .filter(|(_, item)| {
            item.get("deleted") != Some(&Value::Bool(true))
        })
        .map(|(name, _)| name)
        .filter(|name| !mirror_items.is_some_and(|items| items.contains_key(name.as_str())))
        .cloned()
        .collect();
    missing.sort();
    Ok(missing)
}

fn git(args: &[&str]) -> Result<(bool, String, String)> {
    let out = Command::new("git")
        .arg("-C")
        .arg(sync_dir())
        .args(args)
        .output()
        .context("run git")?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

// === bond serve channel (docs/design/bond.md) ===

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

// Replica mode: fetch the whole ciphertext document from a serve channel and
// atomically replace the local vault with it. A replica must never shrink:
// replacing the local vault with a smaller one destroys local-only items, so
// the pull refuses unless forced. The staged file sits next to the live vault
// so the rename is atomic and no reader sees a partial write.
fn cmd_pull(flags: &HashMap<String, String>) -> Result<Value> {
    let from = flags
        .get("from")
        .context("usage: pull --from <base-url> --token <token> [--consumer name] [--force]")?;
    let token = flags.get("token").context("--token required")?;
    let consumer = flags
        .get("consumer")
        .map(String::as_str)
        .unwrap_or("replica");
    let (status, doc) = serve_request(from, "GET", "/v1/vault", consumer, token, None)?;
    if doc.get("items").and_then(Value::as_object).is_none() || doc.get("version").is_none() {
        bail!("remote did not return a vault document (status: {status}, body: {doc})");
    }
    let remote_count = item_count(&doc);
    let live = vault_path();
    let local_count = if live.exists() {
        let local: Value = serde_json::from_str(
            &std::fs::read_to_string(&live)
                .with_context(|| format!("read vault {}", live.display()))?,
        )?;
        item_count(&local)
    } else {
        usize::default()
    };
    if remote_count < local_count && !flags.contains_key("force") {
        return Ok(json!({
            "ok": false,
            "reason": "remote_has_fewer_items",
            "items_before": local_count,
            "items_after": remote_count,
            "detail": "refusing to replace the local vault with a smaller one; re-run with --force to accept the loss"
        }));
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
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "pull" => cmd_pull(flags).map(Some),
        "sync-init" => {
            let remote = positionals
                .first()
                .context("usage: sync-init <remote-url>")?;
            std::fs::create_dir_all(sync_dir())?;
            let (ok, _o, e) = git(&["init"])?;
            if !ok {
                bail!("git init failed: {}", e.trim());
            }
            git(&["remote", "remove", "origin"]).ok();
            let (ok2, _o2, e2) = git(&["remote", "add", "origin", remote])?;
            if !ok2 {
                bail!("git remote add failed: {}", e2.trim());
            }
            crate::runtime::audit::append("sync-init", &json!({"remote": remote}))?;
            Ok(Some(
                json!({"ok": true, "sync_dir": sync_dir().display().to_string(), "remote": remote}),
            ))
        }
        "sync-push" => {
            let live = vault_path();
            if !live.exists() {
                bail!("no vault to push at {}", live.display());
            }
            std::fs::create_dir_all(sync_dir())?;
            std::fs::copy(&live, mirror_path()).context("copy vault into sync dir")?;
            git(&["add", "vault.enc.json"])?;
            let message = flags
                .get("message")
                .map(String::as_str)
                .unwrap_or("skarbiec sync");
            git(&["commit", "-m", message]).ok(); // no-op commit is fine
            let branch = flags.get("branch").map(String::as_str).unwrap_or("main");
            let (ok, _o, e) = git(&["push", "origin", branch])?;
            crate::runtime::audit::append("sync-push", &json!({"branch": branch, "ok": ok}))?;
            Ok(Some(
                json!({"ok": ok, "branch": branch, "detail": e.trim()}),
            ))
        }
        "sync-pull" => {
            let branch = flags.get("branch").map(String::as_str).unwrap_or("main");
            let (ok, _o, e) = git(&["pull", "--no-rebase", "origin", branch])?;
            if !ok {
                return Ok(Some(
                    json!({"ok": false, "reason": "git_pull_failed", "detail": e.trim()}),
                ));
            }
            let mirror = mirror_path();
            if !mirror.exists() {
                bail!("sync repo has no vault.enc.json yet");
            }
            let live = vault_path();
            let mut backup: Option<PathBuf> = None;
            if live.exists() {
                let path = live.with_extension(format!("json.pre-pull-{}", now_stamp()));
                std::fs::copy(&live, &path)
                    .with_context(|| format!("back up live vault to {}", path.display()))?;
                backup = Some(path);
                let missing = items_missing_from_mirror(&live, &mirror)?;
                if !missing.is_empty() && !flags.contains_key("force") {
                    return Ok(Some(json!({
                        "ok": false,
                        "reason": "local_only_items_would_be_lost",
                        "branch": branch,
                        "local_only_items": missing,
                        "backup": backup.map(|p| p.display().to_string()),
                        "detail": "push these items first, or re-run with --force to accept the loss"
                    })));
                }
            }
            std::fs::copy(&mirror, &live).context("copy synced vault into place")?;
            let backup = backup.map(|path| path.display().to_string());
            crate::runtime::audit::append(
                "sync-pull",
                &json!({"branch": branch, "backup": backup}),
            )?;
            Ok(Some(
                json!({"ok": true, "branch": branch, "vault": live.display().to_string(), "backup": backup}),
            ))
        }
        _ => Ok(None),
    }
}
