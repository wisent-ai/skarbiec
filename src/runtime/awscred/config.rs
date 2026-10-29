// `helper setup aws <id> --profile <name>` and `helper unset aws --profile
// <name>`: make one AWS profile read its key from this vault, or stop it. The
// AWS config file (AWS_CONFIG_FILE, else ~/.aws/config) is an INI file whose
// profile sections are `[profile <name>]`, and `[default]` for the default
// profile; setup sets the section's credential_process to this binary's
// `helper answer aws <id>` and keeps every other line as it was. A key written
// into the profile — in the config file or in the shared credentials file
// (AWS_SHARED_CREDENTIALS_FILE, else ~/.aws/credentials), whose sections are
// `[<name>]` — wins over credential_process, so setup refuses a profile that
// still holds one, naming where.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::ops::Range;
use std::path::{Path, PathBuf};

const PROCESS: &str = "credential_process";
const STATIC_KEY: &str = "aws_access_key_id";
const DEFAULT: &str = "default";

fn file(variable: &str, name: &str) -> Result<PathBuf> {
    match crate::core::env::path(variable) {
        Some(path) => Ok(path),
        None => Ok(crate::core::env::path("HOME")
            .with_context(|| {
                format!("neither {variable} nor HOME names where AWS keeps its {name} file")
            })?
            .join(".aws")
            .join(name)),
    }
}

/// The shared credentials file AWS reads static keys from.
pub(super) fn credentials_file() -> Result<PathBuf> {
    file("AWS_SHARED_CREDENTIALS_FILE", "credentials")
}

/// The file's text; a file AWS never wrote holds no profile yet.
pub(super) fn read(path: &Path) -> Result<String> {
    match crate::core::read_present(path, "the AWS file")? {
        Some(text) => Ok(text),
        None => Ok(String::new()),
    }
}

/// The config file's header for `profile`.
fn config_header(profile: &str) -> String {
    match profile == DEFAULT {
        true => format!("[{DEFAULT}]"),
        false => format!("[profile {profile}]"),
    }
}

/// The lines of the section under `header`: from the line after it to the
/// next header or the end of the file, as indexes into `lines`; None when the
/// file has no such section.
pub(super) fn section(lines: &[&str], header: &str) -> Option<Range<usize>> {
    let start = lines
        .iter()
        .position(|line| line.trim() == header)?
        .checked_add(std::iter::once(()).count())?;
    let end = match lines[start..]
        .iter()
        .position(|line| line.trim_start().starts_with('['))
    {
        Some(offset) => start + offset,
        None => lines.len(),
    };
    Some(start..end)
}

/// The index of the line in `range` setting `key`.
fn setting(lines: &[&str], range: Range<usize>, key: &str) -> Option<usize> {
    range.into_iter().find(|&index| {
        lines[index]
            .split_once('=')
            .is_some_and(|(name, _)| name.trim() == key)
    })
}

pub(super) fn setup(id: &str, profile: &str) -> Result<Value> {
    let credentials = file("AWS_SHARED_CREDENTIALS_FILE", "credentials")?;
    let shared = read(&credentials)?;
    let shared_lines: Vec<&str> = shared.lines().collect();
    if let Some(range) = section(&shared_lines, &format!("[{profile}]")) {
        if setting(&shared_lines, range, STATIC_KEY).is_some() {
            bail!(
                "profile {profile} keeps a key in {}, and AWS uses it before any credential_process; `skarbiec helper import aws <id> --profile {profile}` moves it into the vault and points the profile at it",
                credentials.display()
            );
        }
    }
    let path = file("AWS_CONFIG_FILE", "config")?;
    let text = read(&path)?;
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let header = config_header(profile);
    let program = std::env::current_exe()
        .context("name this skarbiec binary for the credential_process line")?;
    let line = format!(
        "{PROCESS} = \"{}\" {} {id}",
        program.display(),
        crate::runtime::helper::invocation(super::TOOL)
    );
    let (found, process, static_key) = {
        let borrowed: Vec<&str> = lines.iter().map(String::as_str).collect();
        match section(&borrowed, &header) {
            Some(range) => (
                Some(range.start),
                setting(&borrowed, range.clone(), PROCESS),
                setting(&borrowed, range, STATIC_KEY),
            ),
            None => (None, None, None),
        }
    };
    if static_key.is_some() {
        bail!("profile {profile} keeps a key in {} itself, which AWS uses before any credential_process; remove its {STATIC_KEY} and aws_secret_access_key lines, then run setup again", path.display());
    }
    match (found, process) {
        (Some(_), Some(index)) => lines[index] = line.clone(),
        (Some(start), None) => lines.insert(start, line.clone()),
        (None, _) => {
            lines.push(header);
            lines.push(line.clone());
        }
    }
    write(&path, &lines)?;
    crate::runtime::audit::append(
        "aws-credential-setup",
        &json!({"item": id, "profile": profile, "config": path}),
    )?;
    Ok(json!({"ok": true, "item": id, "profile": profile, "config": path, "line": line}))
}

pub(super) fn unset(profile: &str) -> Result<Value> {
    let path = file("AWS_CONFIG_FILE", "config")?;
    let text = read(&path)?;
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let index = {
        let borrowed: Vec<&str> = lines.iter().map(String::as_str).collect();
        let range = section(&borrowed, &config_header(profile))
            .with_context(|| format!("{} has no profile {profile}", path.display()))?;
        setting(&borrowed, range, PROCESS).with_context(|| {
            format!(
                "profile {profile} in {} runs no credential_process",
                path.display()
            )
        })?
    };
    if !lines[index].contains(&crate::runtime::helper::invocation(super::TOOL)) {
        bail!("profile {profile}'s credential_process in {} is not this vault's, so it is left alone: {}", path.display(), lines[index]);
    }
    let removed = lines.remove(index);
    write(&path, &lines)?;
    crate::runtime::audit::append(
        "aws-credential-unset",
        &json!({"profile": profile, "config": path}),
    )?;
    Ok(json!({"ok": true, "profile": profile, "config": path, "removed": removed}))
}

pub(super) fn write(path: &Path, lines: &[String]) -> Result<()> {
    let dir = path
        .parent()
        .context("the AWS config file has no directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let mut text = lines.join("\n");
    text.push('\n');
    crate::core::vault::atomic_write(path, text.as_bytes())
        .with_context(|| format!("write {}", path.display()))
}

/// One profile the AWS config file sends to this vault.
pub(crate) struct Profile {
    pub(crate) name: String,
    /// The binary its credential_process runs, as setup quoted it.
    pub(crate) program: PathBuf,
    pub(crate) item: String,
}

/// Every profile in the AWS config file whose credential_process runs this
/// vault's `helper answer aws`, with the program and the item it names, so doctor
/// can check each program is still there.
pub(crate) fn profiles() -> Result<(PathBuf, Vec<Profile>)> {
    let path = file("AWS_CONFIG_FILE", "config")?;
    let text = read(&path)?;
    let mut found = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            current = Some(match name.strip_prefix("profile ") {
                Some(profile) => profile.trim().to_string(),
                None => name.trim().to_string(),
            });
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        if key.trim() != PROCESS {
            continue;
        }
        // setup writes `"<program>" helper answer aws <id>`; any other line
        // is someone else's and not this vault's to check.
        let Some((program, rest)) = value
            .trim()
            .strip_prefix('"')
            .and_then(|quoted| quoted.split_once('"'))
        else {
            continue;
        };
        let words: Vec<&str> = rest.split_whitespace().collect();
        let (Some([item]), Some(name)) = (
            crate::runtime::helper::invoked(super::TOOL, &words),
            &current,
        ) else {
            continue;
        };
        found.push(Profile {
            name: name.clone(),
            program: PathBuf::from(program),
            item: item.to_string(),
        });
    }
    Ok((path, found))
}
