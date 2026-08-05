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
// The bond serve channel (serve-mode `pull`, `GET /v1/vault`, the shared HTTP
// client) lives in net::bond — this module is the git channel only.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use crate::core::vault_path;

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
        .filter(|(_, item)| item.get("deleted") != Some(&Value::Bool(true)))
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

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
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
            let (name_ok, _o, name_error) = git(&["config", "user.name", "Skarbiec Desktop"])?;
            if !name_ok {
                bail!("git user.name configuration failed: {}", name_error.trim());
            }
            let (email_ok, _o, email_error) = git(&["config", "user.email", "skarbiec@localhost"])?;
            if !email_ok {
                bail!(
                    "git user.email configuration failed: {}",
                    email_error.trim()
                );
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
            let remote_ref = format!("HEAD:refs/heads/{branch}");
            let (ok, _o, e) = git(&["push", "origin", &remote_ref])?;
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
