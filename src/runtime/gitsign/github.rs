// `signing setup <id> --github`: GitHub shows a commit signed with an SSH
// key as verified only when that key is among the account's signing keys,
// a list apart from the keys it signs in with. setup adds the item's public
// key there through gh, signed in as the account, before git is told to sign
// with it, titled with the item's id; a key already there is left as it is.
// Only the public key reaches gh. rotate --with ssh --github-signing carries it to
// the next key.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::process::Command;

const PATH: &str = "user/ssh_signing_keys";

fn gh(args: &[&str]) -> Result<Value> {
    let output = stado_wait::output(Command::new("gh").arg("api").args(args))
        .context("run gh api, which adds the GitHub signing key")?;
    if !output.status.success() {
        bail!(
            "gh api {} ({}): {}; gh needs the admin:ssh_signing_key scope, which `gh auth refresh -s admin:ssh_signing_key` grants",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    match text.trim().is_empty() {
        true => Ok(Value::Null),
        false => serde_json::from_str(&text).with_context(|| {
            format!(
                "gh api {} answered something that is not JSON",
                args.join(" ")
            )
        }),
    }
}

/// Make `signing` (type and key, no comment) one of the GitHub account's
/// signing keys, answering whether it was added or already there.
pub(super) fn publish(id: &str, signing: &str) -> Result<Value> {
    let listed = gh(&[PATH])?;
    let present = listed
        .as_array()
        .into_iter()
        .flatten()
        .any(|key| key["key"].as_str().and_then(super::bare).as_deref() == Some(signing));
    if present {
        return Ok(json!({"added": false, "already_there": true}));
    }
    let title = format!("title=skarbiec {id}");
    let key = format!("key={signing}");
    let made = gh(&["-X", "POST", PATH, "-f", title.as_str(), "-f", key.as_str()])?;
    Ok(json!({"added": true, "already_there": false, "id": made["id"]}))
}
