// Whether this host publishes its Git ciphertext mirror, and what the mirror
// last published.
//
// Only the vault's owner publishes: a replica that pushed would replace the
// owner's ciphertext with its own copy, so publishing is never inferred from a
// mirror existing. `mirror publish` records it in the mirror's own Git
// configuration, and every `skarbiec maintain` pass on that host then pushes,
// so the mirror carries the owner's changes instead of the last push someone
// ran by hand. `skarbiec doctor` reads what was last pushed from disk, without
// a fetch, and fails when the live vault changed after it.

use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{branch, checked_git, git, leaf, sync_dir, vault_path};

const PUBLISH_KEY: &str = "skarbiec.publish";

fn has_mirror() -> bool {
    sync_dir().join(".git").exists()
}

/// `mirror publish` (true) and `mirror unpublish` (false).
pub(super) fn set(publish: bool) -> Result<Value> {
    if !has_mirror() {
        bail!(
            "no mirror in {}; `skarbiec mirror init <remote-url>` creates it",
            sync_dir().display()
        );
    }
    checked_git(&["config", "--bool", PUBLISH_KEY, &publish.to_string()])?;
    crate::runtime::audit::append("sync-publish", &json!({"publish": publish}))?;
    Ok(json!({"ok": true, "publish": publish, "sync_dir": sync_dir().display().to_string()}))
}

/// One `mirror push` when this host publishes its mirror, `None` when it does
/// not. A push that fails is the caller's error, naming the Git step.
pub(crate) fn push_if_published() -> Result<Option<Value>> {
    if !has_mirror() {
        return Ok(None);
    }
    // `git config --bool` exits nonzero and says nothing when the key is
    // absent, which is a host that never ran `mirror publish`. A config it
    // cannot read exits nonzero saying why, and that is an error, not a host
    // that does not publish.
    let (set, value, error) = git(&["config", "--bool", PUBLISH_KEY])?;
    if !set && !error.trim().is_empty() {
        bail!(
            "git config --bool {PUBLISH_KEY} in {}: {}",
            sync_dir().display(),
            error.trim()
        );
    }
    if !set || value.trim() != "true" {
        return Ok(None);
    }
    leaf("mirror push", &HashMap::new(), &[])
}

/// What the mirror last published, read from disk: `None` when this host has
/// no mirror, `Ok` when the live vault is the one last pushed, `Err` naming
/// how it differs and when the last push was.
pub(crate) fn published_state() -> Option<std::result::Result<String, String>> {
    if !has_mirror() {
        return None;
    }
    let pushed = match branch(&HashMap::new()) {
        Ok(branch) => format!("refs/remotes/origin/{branch}"),
        Err(error) => return Some(Err(format!("{error:#}"))),
    };
    let at = match git(&["log", "-1", "--format=%cI", &pushed]) {
        Ok((true, at, _)) if !at.trim().is_empty() => at.trim().to_string(),
        Ok((_, _, error)) => {
            return Some(Err(format!(
                "the mirror in {} has never pushed {pushed}: {}",
                sync_dir().display(),
                error.trim()
            )))
        }
        Err(error) => return Some(Err(format!("{error:#}"))),
    };
    let live = match std::fs::read_to_string(vault_path()) {
        Ok(live) => live,
        Err(error) => return Some(Err(format!("read {}: {error}", vault_path().display()))),
    };
    Some(match git(&["show", &format!("{pushed}:vault.enc.json")]) {
        Ok((true, mirror, _)) if mirror == live => {
            Ok(format!("the live vault is the one pushed to {pushed} at {at}"))
        }
        Ok((true, _, _)) => Err(format!(
            "the live vault changed after the last push to {pushed}, at {at}, and nothing published it since"
        )),
        Ok((false, _, error)) => Err(format!("git show {pushed}:vault.enc.json: {}", error.trim())),
        Err(error) => Err(format!("{error:#}")),
    })
}
