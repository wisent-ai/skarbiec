// Git-backed multi-device sync. The vault file is ciphertext, so it is safe to
// commit and push to a remote and pull back on another device. A dedicated sync
// directory (a git repo) holds a copy named vault.enc.json; push copies the
// live vault into it and commits+pushes, pull fetches and copies it back.
//
// A pull replaces the whole live vault, so it can destroy items that exist only
// locally (created after the last push). `mirror pull` therefore snapshots the
// live vault first and refuses to proceed when local-only items would be lost,
// unless `--force` is given. Merging is deliberately not attempted: mirror and
// live vault may be encrypted to different recipient sets.
//
// The bond serve channel (serve-mode `pull`, `GET /v1/vault`, the shared HTTP
// client) lives in net::bond — this module is the git channel only.

use crate::cli::args::OrUsage;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use crate::core::vault_path;

mod published;
pub(crate) use published::{published_state, push_if_published};

fn sync_dir() -> PathBuf {
    if let Some(directory) = crate::core::env::path("SKARBIEC_SYNC_DIR") {
        return directory;
    }
    crate::core::home_dir().join(".skarbiec-sync")
}

fn mirror_path() -> PathBuf {
    sync_dir().join("vault.enc.json")
}

fn now_stamp() -> String {
    crate::core::clock::now_stamp()
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
    let out = stado_wait::output(Command::new("git").arg("-C").arg(sync_dir()).args(args))
        .with_context(|| format!("run git {} in {}", args.join(" "), sync_dir().display()))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

fn checked_git(args: &[&str]) -> Result<String> {
    let (ok, stdout, stderr) = git(args)?;
    if !ok {
        bail!(
            "mirror: git {} in {} failed: {}; {}",
            args.join(" "),
            sync_dir().display(),
            stderr.trim(),
            stdout.trim()
        );
    }
    Ok(stdout)
}

/// The branch `--branch` names, else the one the mirror has checked out:
/// `mirror init` creates `main`, and a mirror made elsewhere says its own.
fn branch(flags: &HashMap<String, String>) -> Result<String> {
    if let Some(branch) = flags.get("branch") {
        return Ok(branch.clone());
    }
    Ok(checked_git(&["symbolic-ref", "--short", "HEAD"])?
        .trim()
        .to_string())
}

/// `mirror init|push|pull` is a group over the Git ciphertext mirror: the
/// object is the command and the verb its first positional; the operator
/// routes call the leaves by their whole name ("mirror push"). The old
/// spellings sync-init, sync-push and sync-pull are gone: Stado runs the
/// group. Audit operation names are unchanged.
pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command == "mirror" {
        return group(flags, positionals).map(Some);
    }
    leaf(command, flags, positionals)
}

fn group(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let Some((verb, positionals)) = positionals.split_first() else {
        return Err(crate::cli::args::Usage(
            "mirror needs a subcommand; `skarbiec mirror help` lists them".to_string(),
        )
        .into());
    };
    if verb == "help" {
        return Ok(json!({
            "commands": [
                "mirror init <remote-url>",
                "mirror push [--branch <name>] [--message <text>]",
                "mirror pull [--branch <name>] [--force]",
                "mirror publish",
                "mirror unpublish",
            ],
            "usage": "mirror init sets up the Git ciphertext mirror on branch main and its origin, mirror push commits the encrypted vault and pushes the mirror's branch, mirror pull replaces the live vault from the mirror after backing it up, refusing while local items would be lost unless --force. mirror publish makes every `skarbiec maintain` pass on this host push the mirror, which only the vault's owner may do; mirror unpublish stops it.",
        }));
    }
    leaf(&format!("mirror {verb}"), flags, positionals)?.ok_or_else(|| {
        crate::cli::args::Usage(format!(
            "unknown mirror command: {verb}; `skarbiec mirror help` lists them"
        ))
        .into()
    })
}

fn leaf(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "mirror init" => {
            let remote = positionals
                .first()
                .or_usage("usage: mirror init <remote-url>")?;
            std::fs::create_dir_all(sync_dir())?;
            let (ok, _o, e) = git(&["init", "--initial-branch", "main"])?;
            if !ok {
                bail!("git init failed: {}", e.trim());
            }
            if git(&["remote", "get-url", "origin"])?.0 {
                checked_git(&["remote", "remove", "origin"])?;
            }
            let (ok2, _o2, e2) = git(&["remote", "add", "origin", remote])?;
            if !ok2 {
                bail!("git remote add failed: {}", e2.trim());
            }
            let (name_ok, _o, name_error) = git(&["config", "user.name", "Skarbiec Desktop"])?;
            if !name_ok {
                bail!("git user.name configuration failed: {}", name_error.trim());
            }
            let (email_ok, _o, email_error) = git(&["config", "user.email", "skarbiec-mirror"])?;
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
        "mirror push" => {
            let live = vault_path();
            if !crate::core::is_present(&live, "vault")? {
                bail!("no vault to push at {}", live.display());
            }
            std::fs::create_dir_all(sync_dir())?;
            std::fs::copy(&live, mirror_path()).context("copy vault into sync dir")?;
            checked_git(&["add", "vault.enc.json"])?;
            let message = match flags.get("message") {
                Some(message) => message.clone(),
                None => format!("skarbiec mirror push of {}", live.display()),
            };
            let staged = checked_git(&["diff", "--cached", "--name-only", "--", "vault.enc.json"])?;
            if !staged.trim().is_empty() {
                checked_git(&["commit", "-m", &message, "--only", "--", "vault.enc.json"])?;
            }
            let branch = branch(flags)?;
            let remote_ref = format!("HEAD:refs/heads/{branch}");
            let (ok, _o, e) = git(&["push", "origin", &remote_ref])?;
            crate::runtime::audit::append("sync-push", &json!({"branch": branch, "ok": ok}))?;
            if !ok {
                bail!(
                    "mirror push: git push origin {remote_ref} failed: {}",
                    e.trim()
                );
            }
            Ok(Some(
                json!({"ok": true, "branch": branch, "detail": e.trim()}),
            ))
        }
        "mirror publish" => published::set(true).map(Some),
        "mirror unpublish" => published::set(false).map(Some),
        "mirror pull" => {
            let branch = branch(flags)?;
            let (ok, _o, e) = git(&["pull", "--no-rebase", "origin", &branch])?;
            if !ok {
                bail!("mirror pull: git pull origin {branch} failed: {}", e.trim());
            }
            let mirror = mirror_path();
            if !crate::core::is_present(&mirror, "synced vault")? {
                bail!("sync repo has no vault.enc.json yet");
            }
            let live = vault_path();
            let mut backup: Option<PathBuf> = None;
            // A live vault that cannot be examined is refused, not read as
            // absent: as absent it was overwritten by the mirror unbacked and
            // unchecked for local items the mirror lacks.
            if crate::core::is_present(&live, "live vault")? {
                let path = live.with_extension(format!("json.pre-pull-{}", now_stamp()));
                std::fs::copy(&live, &path)
                    .with_context(|| format!("back up live vault to {}", path.display()))?;
                backup = Some(path);
                let missing = items_missing_from_mirror(&live, &mirror)?;
                if !missing.is_empty() && !flags.contains_key("force") {
                    bail!(
                        "mirror pull: {} local item(s) are not in the mirror and would be lost: {}; the live vault is unchanged and backed up at {}. Push them first, or re-run with --force to accept the loss",
                        missing.len(),
                        missing.join(", "),
                        backup.map(|p| p.display().to_string()).unwrap_or_default()
                    );
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
