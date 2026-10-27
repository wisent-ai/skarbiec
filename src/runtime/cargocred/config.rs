// The files `helper setup|unset|import cargo` change: Cargo's configuration
// ($CARGO_HOME/config.toml, else ~/.cargo/config.toml), whose
// [registry] global-credential-providers names the providers Cargo asks for
// a registry's token, and credentials.toml beside it, where `cargo login`
// leaves tokens in plain text — [registry] token for crates.io and
// [registries.<name>] token for the others. Both are edited line by line:
// only the lines this vault writes or removes change, and a file that names
// another global provider list is left for the person to merge.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const KEY: &str = "global-credential-providers";
const TABLE: &str = "[registry]";

fn cargo_home() -> Result<PathBuf> {
    match crate::core::env::path("CARGO_HOME") {
        Some(dir) => Ok(dir),
        None => Ok(crate::core::env::path("HOME").context("neither CARGO_HOME nor HOME names where Cargo keeps its configuration")?.join(".cargo")),
    }
}

pub(super) fn config_file() -> Result<PathBuf> {
    Ok(cargo_home()?.join("config.toml"))
}

pub(super) fn credentials_file() -> Result<PathBuf> {
    Ok(cargo_home()?.join("credentials.toml"))
}

fn read(file: &Path, what: &str) -> Result<String> {
    match crate::core::read_present(file, what)? {
        Some(text) => Ok(text),
        None => Ok(String::new()),
    }
}

fn write(file: &Path, lines: &[String]) -> Result<()> {
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    crate::core::vault::atomic_write(file, out.as_bytes()).with_context(|| format!("write {}", file.display()))
}

/// The provider line this binary answers as: Cargo's own token-from-stdout
/// provider running `skarbiec helper answer cargo`.
fn provider() -> Result<String> {
    let binary = std::env::current_exe().context("find this skarbiec binary's path for Cargo to run")?;
    let binary = binary.to_str().context("this binary's path is not text Cargo's configuration can carry")?.to_string();
    if binary.contains('"') || binary.contains(' ') {
        bail!("this binary's path {binary} holds a quote or space, which Cargo's provider line cannot carry");
    }
    Ok(format!("{KEY} = [\"cargo:token-from-stdout {binary} {}\"]", crate::runtime::helper::invocation(super::TOOL)))
}

/// What this vault's provider line ends with: the invocation, then the
/// closing quote of the provider's entry.
fn ours() -> String {
    format!(" {}\"", crate::runtime::helper::invocation(super::TOOL))
}

/// Where the provider line sits, and whether it is this vault's.
fn provider_line(lines: &[&str]) -> Option<(usize, bool)> {
    lines.iter().position(|line| line.trim_start().starts_with(KEY)).map(|at| (at, lines[at].contains(&ours())))
}

pub(super) fn setup() -> Result<Value> {
    let file = config_file()?;
    let text = read(&file, "Cargo's config.toml")?;
    let lines: Vec<&str> = text.lines().collect();
    let line = provider()?;
    let written = match provider_line(&lines) {
        Some((_, true)) => false,
        Some((at, false)) => bail!("{} already sets `{}`; add this vault's provider to that list by hand: {line}", file.display(), lines[at].trim()),
        None => {
            let mut kept: Vec<String> = lines.iter().map(|text| (*text).to_string()).collect();
            match lines.iter().position(|text| text.trim() == TABLE) {
                Some(at) => kept.insert(at + std::iter::once(()).count(), line.clone()),
                None => {
                    if kept.last().is_some_and(|text| !text.trim().is_empty()) {
                        kept.push(String::new());
                    }
                    kept.push(TABLE.to_string());
                    kept.push(line.clone());
                }
            }
            write(&file, &kept)?;
            true
        }
    };
    let left = stored_registries()?;
    crate::runtime::audit::append("cargo-credential-setup", &json!({"config": file}))?;
    Ok(json!({
        "ok": true,
        "config": file,
        "written": written,
        "line": line,
        "plain_tokens": {"file": credentials_file()?, "registries": left},
        "next": "Cargo now asks this vault for a registry's token: the login offered on the registry's index host answers; `skarbiec helper import cargo <id> --registry <name> --host <index host>` moves a token credentials.toml still holds",
    }))
}

pub(super) fn unset() -> Result<Value> {
    let file = config_file()?;
    let text = read(&file, "Cargo's config.toml")?;
    let lines: Vec<&str> = text.lines().collect();
    let Some((at, true)) = provider_line(&lines) else {
        bail!("{} names no skarbiec credential provider; nothing was changed", file.display());
    };
    let kept: Vec<String> = lines.iter().enumerate().filter(|(index, _)| *index != at).map(|(_, text)| (*text).to_string()).collect();
    write(&file, &kept)?;
    crate::runtime::audit::append("cargo-credential-unset", &json!({"config": file}))?;
    Ok(json!({"ok": true, "config": file}))
}

pub(super) fn status() -> Result<Value> {
    let file = config_file()?;
    let text = read(&file, "Cargo's config.toml")?;
    let lines: Vec<&str> = text.lines().collect();
    let (configured, other, program) = match provider_line(&lines) {
        Some((at, true)) => {
            // The binary the line runs: between the provider's name and the
            // command this vault answers as.
            let program = lines[at]
                .split_once("cargo:token-from-stdout ")
                .and_then(|(_, rest)| rest.split_once(ours().as_str()))
                .map(|(binary, _)| binary.to_string());
            (true, Value::Null, json!(program))
        }
        Some((at, false)) => (false, json!(lines[at].trim()), Value::Null),
        None => (false, Value::Null, Value::Null),
    };
    Ok(json!({
        "ok": true,
        "config": file,
        "configured": configured,
        "program": program,
        "other_providers": other,
        "credentials": credentials_file()?,
        "registries_in_file": stored_registries()?,
    }))
}

/// The registry a credentials.toml table header names: crates-io for
/// [registry], <name> for [registries.<name>].
fn table_registry(header: &str) -> Option<String> {
    match header {
        TABLE => Some("crates-io".to_string()),
        _ => header.strip_prefix("[registries.").and_then(|rest| rest.strip_suffix(']')).map(str::to_string),
    }
}

/// Every registry credentials.toml keeps a token for, with the line it is on
/// and the token.
pub(super) fn stored_tokens() -> Result<(PathBuf, Vec<String>, Vec<(String, usize, String)>)> {
    let file = credentials_file()?;
    let text = read(&file, "Cargo's credentials.toml")?;
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut found = Vec::new();
    let mut current: Option<String> = None;
    for (at, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            current = table_registry(trimmed);
            continue;
        }
        let Some(registry) = &current else { continue };
        let Some((key, value)) = trimmed.split_once('=') else { continue };
        if key.trim() == "token" {
            let token = value.trim().trim_matches('"').to_string();
            found.push((registry.clone(), at, token));
        }
    }
    Ok((file, lines, found))
}

fn stored_registries() -> Result<Vec<String>> {
    Ok(stored_tokens()?.2.into_iter().map(|(registry, _, _)| registry).collect())
}

/// Write credentials.toml back without the line at `at`.
pub(super) fn remove_line(file: &Path, lines: &[String], at: usize) -> Result<()> {
    let kept: Vec<String> = lines.iter().enumerate().filter(|(index, _)| *index != at).map(|(_, text)| text.clone()).collect();
    write(file, &kept)
}
