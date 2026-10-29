// `skarbiec helper setup git <host>` and `helper unset git <host>`: make git ask this
// vault for one forge's https credentials, or stop it, by git's own per-site
// setting `credential.https://<host>.helper` in the user's global git
// configuration. The helper is named by this binary's absolute path, so git
// finds it whatever PATH the shell that runs git has.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::process::Command;

use crate::cli::args::Usage;

/// A host as git names it in a request: letters, digits, dots and hyphens,
/// with an optional port after a colon.
pub(crate) fn checked(host: &str) -> Result<&str> {
    let (name, port) = match host.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };
    let name_ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    let port_ok =
        port.is_none_or(|digits| !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()));
    if !(name_ok && port_ok) {
        return Err(Usage(format!(
            "{host} is not a host as git names one: a name such as github.com, with a port after a colon when the forge uses one"
        ))
        .into());
    }
    Ok(host)
}

fn key(host: &str) -> String {
    format!("credential.https://{host}.helper")
}

fn git(args: &[&str]) -> Result<std::process::Output> {
    stado_wait::output(Command::new("git").args(args))
        .context("run git config, which keeps git's credential helpers")
}

/// Every forge the user's global git configuration asks a skarbiec binary
/// for: its host and the program path the setting names, so doctor can say
/// when that program has moved away. git config answers nothing, and fails
/// without a word, when no setting matches.
pub(crate) fn configured() -> Result<Vec<(String, std::path::PathBuf)>> {
    let found = git(&[
        "config",
        "--global",
        "--get-regexp",
        r"^credential\..*\.helper$",
    ])?;
    if !found.status.success() {
        if found.stdout.is_empty() && found.stderr.is_empty() {
            return Ok(Vec::new());
        }
        bail!(
            "git config could not list credential helpers ({}): {}",
            found.status,
            String::from_utf8_lossy(&found.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&found.stdout).to_string();
    Ok(text
        .lines()
        .filter_map(|line| {
            let (setting, helper) = line.split_once(' ')?;
            let host = setting
                .strip_prefix("credential.https://")?
                .strip_suffix(".helper")?;
            let program = helper.strip_prefix('!')?.strip_suffix(
                format!(" {}", crate::runtime::helper::invocation(super::TOOL)).as_str(),
            )?;
            Some((host.to_string(), std::path::PathBuf::from(program)))
        })
        .collect())
}

pub fn setup(host: &str) -> Result<Value> {
    let host = checked(host)?;
    let binary =
        std::env::current_exe().context("find this skarbiec binary's path for git to run")?;
    let helper = format!(
        "!{} {}",
        binary.display(),
        crate::runtime::helper::invocation(super::TOOL)
    );
    let setting = key(host);
    let done = git(&["config", "--global", &setting, &helper])?;
    if !done.status.success() {
        bail!(
            "git config refused to set {setting} ({}): {}",
            done.status,
            String::from_utf8_lossy(&done.stderr).trim()
        );
    }
    crate::runtime::audit::append("git-credential-setup", &json!({"host": host}))?;
    Ok(json!({"ok": true, "host": host, "setting": setting, "helper": helper}))
}

pub fn unset(host: &str) -> Result<Value> {
    let host = checked(host)?;
    let setting = key(host);
    let done = git(&["config", "--global", "--unset-all", &setting])?;
    if !done.status.success() {
        bail!(
            "git config could not remove {setting} ({}): {}; `git config --global --get-all {setting}` shows whether it is set",
            done.status,
            String::from_utf8_lossy(&done.stderr).trim()
        );
    }
    crate::runtime::audit::append("git-credential-unset", &json!({"host": host}))?;
    Ok(json!({"ok": true, "host": host, "removed": setting}))
}
