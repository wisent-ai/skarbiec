// `rotate <id> --with ssh --hosts <user@host,...>`: carry a rotation to the
// servers that trust the key, so nothing is left to paste. For every host,
// with the old key: the new public key is added to ~/.ssh/authorized_keys;
// then the new key must log in. Only when every host accepts the new key is
// it stored in the vault, and the old line is then removed from each host
// with the new key. When a host fails, the new line is taken back off every
// host it was added to, with the old key, and the vault keeps the old pair —
// no host is left trusting a key the vault does not hold.
//
// Keys reach ssh only as files in an owner-only workspace beside the vault,
// removed before the answer. ssh runs in batch mode against the user's own
// known_hosts, so an unknown host key is refused by ssh, never accepted.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;

/// The remote script, run by the login shell of the account: add or remove
/// one exact line of ~/.ssh/authorized_keys, written beside it and moved over
/// it, so a broken connection never leaves half a file. The line arrives as
/// the script's argument through `sh -s`, never through the remote shell's
/// parsing of the command line.
const ADD: &str = r#"set -e; umask 077; mkdir -p ~/.ssh; f=~/.ssh/authorized_keys; touch "$f"; grep -qxF -- "$1" "$f" || printf '%s\n' "$1" >> "$f""#;
const REMOVE: &str = r#"set -e; umask 077; f=~/.ssh/authorized_keys; t="$f.skarbiec.$$"; grep -vxF -- "$1" "$f" > "$t" || true; mv "$t" "$f""#;

/// Write one private key owner-only into the workspace for ssh's -i.
fn key_file(dir: &Path, name: &str, private_key: &str) -> Result<std::path::PathBuf> {
    let path = dir.join(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(crate::core::mode::OWNER_READ_WRITE)
        .open(&path)
        .with_context(|| format!("write the key file {}", path.display()))?;
    let mut text = private_key.to_string();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    std::io::Write::write_all(&mut file, text.as_bytes())
        .with_context(|| format!("write the key file {}", path.display()))?;
    Ok(path)
}

/// Run one script on one host with one key; the line is the script's $1.
fn remote(key: &Path, host: &str, script: &str, line: &str) -> Result<()> {
    let mut command = Command::new("ssh");
    command
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-i",
        ])
        .arg(key)
        .args([host, "sh", "-s", "--"])
        .arg(format!("'{}'", line.replace('\'', r"'\''")))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().context("start ssh")?;
    std::io::Write::write_all(
        child
            .stdin
            .as_mut()
            .context("ssh was started without a standard input")?,
        script.as_bytes(),
    )
    .context("hand the script to ssh")?;
    drop(child.stdin.take());
    let output = stado_wait::blocking(
        stado_wait::Kind::Process,
        "ssh changing authorized_keys",
        host,
        || child.wait_with_output(),
    )
    .context("wait for ssh")?;
    if !output.status.success() {
        bail!(
            "ssh {host} ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Put `new_public` on every host with the old key and prove the new key
/// logs in; on any failure take it back off the hosts it reached. Returns
/// once every host accepts the new key.
pub(super) fn add_everywhere(
    dir: &Path,
    hosts: &[String],
    old_private: &str,
    new_private: &str,
    new_public: &str,
) -> Result<()> {
    let old_key = key_file(dir, "old", old_private)?;
    let new_key = key_file(dir, "new", new_private)?;
    let mut reached: Vec<&String> = Vec::new();
    let mut failure = None;
    for host in hosts {
        let added = remote(&old_key, host, ADD, new_public);
        if added.is_ok() {
            reached.push(host);
        }
        let proven = added.and_then(|()| {
            remote(&new_key, host, "true", new_public).context("the new key does not log in")
        });
        if let Err(error) = proven {
            failure = Some(format!("{host}: {error:#}"));
            break;
        }
    }
    let Some(failure) = failure else {
        return Ok(());
    };
    let mut left = Vec::new();
    for host in reached {
        if let Err(error) = remote(&old_key, host, REMOVE, new_public) {
            left.push(format!("{host}: {error:#}"));
        }
    }
    if left.is_empty() {
        bail!("{failure}; the new key was taken back off every host it reached and the vault keeps the old one");
    }
    bail!(
        "{failure}; the vault keeps the old key, but the new public key could not be taken back off {} — remove it there by hand: {new_public}",
        left.join("; ")
    );
}

/// With the new key, remove the retired line from every host; a host that
/// refuses is named, the others still lose it.
pub(super) fn retire_everywhere(
    dir: &Path,
    hosts: &[String],
    new_private: &str,
    old_public: &str,
) -> Result<Vec<Value>> {
    let new_key = dir.join("new");
    let new_key = if crate::core::is_present(&new_key, "the staged new key")? {
        new_key
    } else {
        key_file(dir, "new", new_private)?
    };
    Ok(hosts
        .iter()
        .map(|host| match remote(&new_key, host, REMOVE, old_public) {
            Ok(()) => json!({"host": host, "retired_removed": true}),
            Err(error) => {
                json!({"host": host, "retired_removed": false, "error": format!("{error:#}")})
            }
        })
        .collect())
}
