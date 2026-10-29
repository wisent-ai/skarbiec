// The files `helper setup|unset terraform` change: Terraform's CLI configuration
// (TF_CLI_CONFIG_FILE, else ~/.terraformrc), which names one credentials
// helper; the plugin directory (~/.terraform.d/plugins) Terraform finds the
// helper program terraform-credentials-<name> in; and credentials.tfrc.json
// (TF_CLI_CONFIG_DIR's, else ~/.terraform.d's), where `terraform login`
// leaves tokens in plain text. Terraform reads that file only while no
// helper is configured, so setup names every host it still holds.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

use super::PROGRAM;

/// The block setup writes and unset removes, line for line.
const BLOCK: &[&str] = &["credentials_helper \"skarbiec\" {", "  args = []", "}"];
/// What any credentials helper block starts with; Terraform takes one.
const ANY_HELPER: &str = "credentials_helper ";
const CREDENTIALS: &str = "credentials";

fn home() -> Result<PathBuf> {
    crate::core::env::path("HOME")
        .context("HOME names no directory where Terraform keeps its configuration")
}

pub(super) fn cli_config() -> Result<PathBuf> {
    match crate::core::env::path("TF_CLI_CONFIG_FILE") {
        Some(file) => Ok(file),
        None => Ok(home()?.join(".terraformrc")),
    }
}

fn terraform_dir() -> Result<PathBuf> {
    match crate::core::env::path("TF_CLI_CONFIG_DIR") {
        Some(dir) => Ok(dir),
        None => Ok(home()?.join(".terraform.d")),
    }
}

pub(super) fn plugin() -> Result<PathBuf> {
    Ok(home()?.join(".terraform.d").join("plugins").join(PROGRAM))
}

pub(super) fn tokens_file() -> Result<PathBuf> {
    Ok(terraform_dir()?.join("credentials.tfrc.json"))
}

fn read_text(file: &Path) -> Result<String> {
    match crate::core::read_present(file, "Terraform's CLI configuration")? {
        Some(text) => Ok(text),
        None => Ok(String::new()),
    }
}

/// Where in `lines` this vault's block starts, if it is there.
fn ours(lines: &[&str]) -> Option<usize> {
    lines.windows(BLOCK.len()).position(|window| {
        window
            .iter()
            .zip(BLOCK)
            .all(|(line, wanted)| line.trim_end() == *wanted)
    })
}

/// The credentials helper Terraform's configuration names, other than this
/// vault's, as the line naming it.
fn other_helper(lines: &[&str]) -> Option<String> {
    let skip = ours(lines);
    lines
        .iter()
        .enumerate()
        .filter(|(index, _)| Some(*index) != skip)
        .find(|(_, line)| line.trim_start().starts_with(ANY_HELPER))
        .map(|(_, line)| line.trim().to_string())
}

/// The hosts credentials.tfrc.json holds a token for, and its members.
pub(super) fn stored_tokens() -> Result<(PathBuf, Map<String, Value>)> {
    let file = tokens_file()?;
    let Some(text) = crate::core::read_present(&file, "Terraform's credentials.tfrc.json")? else {
        return Ok((file, Map::new()));
    };
    match serde_json::from_str(&text).with_context(|| format!("{} is not JSON", file.display()))? {
        Value::Object(members) => Ok((file, members)),
        _ => bail!(
            "{} is not a JSON object; nothing was changed",
            file.display()
        ),
    }
}

fn hosts_in(members: &Map<String, Value>) -> Vec<String> {
    members
        .get(CREDENTIALS)
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(host, _)| host.clone())
        .collect()
}

/// Link the helper program to this binary; one already linked here is kept,
/// one naming anything else is refused.
fn link(program: &Path) -> Result<()> {
    let binary =
        std::env::current_exe().context("find this skarbiec binary's path for Terraform to run")?;
    match std::fs::read_link(program) {
        Ok(target) if target == binary => return Ok(()),
        Ok(target) => bail!(
            "{} already links to {}; remove it first",
            program.display(),
            target.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
            bail!(
                "{} exists and is not a link; remove it first",
                program.display()
            )
        }
        Err(error) => {
            return Err(error).with_context(|| format!("read the link {}", program.display()))
        }
    }
    let dir = program
        .parent()
        .context("the plugin path has no directory")?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create Terraform's plugin directory {}", dir.display()))?;
    std::os::unix::fs::symlink(&binary, program)
        .with_context(|| format!("link {} to {}", program.display(), binary.display()))
}

pub(super) fn setup() -> Result<Value> {
    let file = cli_config()?;
    let text = read_text(&file)?;
    let lines: Vec<&str> = text.lines().collect();
    if let Some(other) = other_helper(&lines) {
        bail!("{} already names a credentials helper, `{other}`, and Terraform takes one; remove that block first", file.display());
    }
    let program = plugin()?;
    link(&program)?;
    let written = match ours(&lines) {
        Some(_) => false,
        None => {
            let mut kept: Vec<String> = lines.iter().map(|line| (*line).to_string()).collect();
            if kept.last().is_some_and(|line| !line.trim().is_empty()) {
                kept.push(String::new());
            }
            kept.extend(BLOCK.iter().map(|line| (*line).to_string()));
            let mut out = kept.join("\n");
            out.push('\n');
            crate::core::vault::atomic_write(&file, out.as_bytes())
                .with_context(|| format!("write Terraform's {}", file.display()))?;
            true
        }
    };
    let (tokens, members) = stored_tokens()?;
    let left = hosts_in(&members);
    crate::runtime::audit::append(
        "terraform-credential-setup",
        &json!({"config": file, "program": program}),
    )?;
    Ok(json!({
        "ok": true,
        "config": file,
        "written": written,
        "program": program,
        "no_longer_read": {"file": tokens, "hosts": left},
        "next": "Terraform now asks this vault for every host's token: each host is answered with the password of the login offered on it; `skarbiec helper import terraform <id> --host <host>` moves a token credentials.tfrc.json still holds into the vault",
    }))
}

pub(super) fn unset() -> Result<Value> {
    let file = cli_config()?;
    let text = read_text(&file)?;
    let lines: Vec<&str> = text.lines().collect();
    let Some(start) = ours(&lines) else {
        bail!(
            "{} names no skarbiec credentials helper; nothing was changed",
            file.display()
        );
    };
    let kept: Vec<&str> = lines
        .iter()
        .enumerate()
        .filter(|(index, _line)| !(start..start + BLOCK.len()).contains(index))
        .map(|(_index, line)| *line)
        .collect();
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    let program = plugin()?;
    let binary = std::env::current_exe().context("find this skarbiec binary's path")?;
    // Read before anything is changed, so an unreadable program refuses the
    // whole unset. A link to another program is not this binary's to remove,
    // and an absent program or a plain file is no link at all.
    let ours = match std::fs::read_link(&program) {
        Ok(target) => target == binary,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
            ) =>
        {
            false
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("read the link {}; nothing was changed", program.display())
            });
        }
    };
    crate::core::vault::atomic_write(&file, out.as_bytes())
        .with_context(|| format!("write Terraform's {}", file.display()))?;
    if ours {
        std::fs::remove_file(&program).with_context(|| format!("remove {}", program.display()))?;
    }
    let unlinked = ours;
    crate::runtime::audit::append("terraform-credential-unset", &json!({"config": file}))?;
    Ok(json!({"ok": true, "config": file, "program": program, "unlinked": unlinked}))
}

/// Whether Terraform asks this vault: the configuration, the program it
/// runs, and the hosts credentials.tfrc.json still holds a token for.
pub(super) fn status() -> Result<Value> {
    let file = cli_config()?;
    let text = read_text(&file)?;
    let lines: Vec<&str> = text.lines().collect();
    let program = plugin()?;
    let linked = match std::fs::read_link(&program) {
        Ok(target) => crate::core::is_present(&target, "the helper program's link target")?,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
            ) =>
        {
            false
        }
        Err(error) => {
            return Err(error).with_context(|| format!("read the link {}", program.display()))
        }
    };
    let (tokens, members) = stored_tokens()?;
    Ok(json!({
        "ok": true,
        "config": file,
        "configured": ours(&lines).is_some(),
        "other_helper": other_helper(&lines),
        "program": program,
        "program_present": linked,
        "tokens_file": tokens,
        "hosts_in_file": hosts_in(&members),
    }))
}

/// Take one host's token out of credentials.tfrc.json, writing the rest back.
pub(super) fn remove_token(file: &Path, mut members: Map<String, Value>, host: &str) -> Result<()> {
    let removed = members
        .get_mut(CREDENTIALS)
        .and_then(Value::as_object_mut)
        .and_then(|hosts| hosts.remove(host));
    if removed.is_none() {
        bail!("{} holds no token for {host}", file.display());
    }
    let text = serde_json::to_string_pretty(&Value::Object(members))?;
    crate::core::vault::atomic_write(file, text.as_bytes())
        .with_context(|| format!("write {}", file.display()))
}

/// The token credentials.tfrc.json holds for `host`.
pub(super) fn token_for(members: &Map<String, Value>, host: &str) -> Option<String> {
    members
        .get(CREDENTIALS)?
        .get(host)?
        .get("token")?
        .as_str()
        .map(str::to_string)
}
