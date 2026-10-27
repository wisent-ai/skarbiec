// `skarbiec helper setup docker <registry> --link <dir>` and `helper unset
// docker <registry>`: make Docker ask this vault for one registry's credentials, or
// stop it. Docker runs a helper by the program name docker-credential-<name>
// found on PATH, chosen per registry by the credHelpers object of its
// config.json (in DOCKER_CONFIG, else ~/.docker). setup links that program
// name, in a directory the person names, to this binary and sets the
// registry's entry; every other member of config.json is kept as it was.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

use super::PROGRAM;
use crate::cli::args::Usage;

/// The helper name Docker's credHelpers entries use for this vault.
const HELPER: &str = "skarbiec";
const HELPERS: &str = "credHelpers";

pub(super) fn config_file() -> Result<PathBuf> {
    let dir = match crate::core::env::path("DOCKER_CONFIG") {
        Some(dir) => dir,
        None => crate::core::env::path("HOME")
            .context("neither DOCKER_CONFIG nor HOME names where Docker keeps config.json")?
            .join(".docker"),
    };
    Ok(dir.join("config.json"))
}

pub(super) fn read_config(file: &Path) -> Result<Map<String, Value>> {
    if !file.exists() {
        return Ok(Map::new());
    }
    let text = std::fs::read_to_string(file).with_context(|| format!("read Docker's {}", file.display()))?;
    match serde_json::from_str(&text).with_context(|| format!("Docker's {} is not JSON", file.display()))? {
        Value::Object(members) => Ok(members),
        _ => bail!("Docker's {} is not a JSON object; nothing was changed", file.display()),
    }
}

pub(super) fn write_config(file: &Path, members: Map<String, Value>) -> Result<()> {
    let dir = file.parent().context("Docker's config.json has no directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let text = serde_json::to_string_pretty(&Value::Object(members))?;
    crate::core::vault::atomic_write(file, text.as_bytes()).with_context(|| format!("write Docker's {}", file.display()))
}

/// The program Docker runs, linked to this binary in `dir`; a link that is
/// already there is kept when it names this binary and refused when it names
/// anything else.
fn link(dir: &str) -> Result<PathBuf> {
    let dir = Path::new(dir);
    if !dir.is_absolute() || !dir.is_dir() {
        return Err(Usage(format!("--link {} must be an existing directory named by an absolute path, one on PATH", dir.display())).into());
    }
    let binary = std::env::current_exe().context("find this skarbiec binary's path for Docker to run")?;
    let program = dir.join(PROGRAM);
    match std::fs::read_link(&program) {
        Ok(target) if target == binary => return Ok(program),
        Ok(target) => bail!("{} already links to {}; remove it or name another directory", program.display(), target.display()),
        Err(error) if program.exists() => {
            bail!("{} exists and is not a link ({error}); remove it or name another directory", program.display())
        }
        Err(_absent) => {}
    }
    std::os::unix::fs::symlink(&binary, &program)
        .with_context(|| format!("link {} to {}", program.display(), binary.display()))?;
    Ok(program)
}

pub(super) fn setup(registry: &str, dir: &str) -> Result<Value> {
    let registry = crate::runtime::gitcred::checked_host(registry)?;
    let program = link(dir)?;
    let file = config_file()?;
    let mut members = read_config(&file)?;
    let helpers = members.entry(HELPERS).or_insert_with(|| json!({}));
    let Some(helpers) = helpers.as_object_mut() else {
        bail!("{HELPERS} in Docker's {} is not an object; nothing was changed", file.display());
    };
    helpers.insert(registry.to_string(), json!(HELPER));
    write_config(&file, members)?;
    crate::runtime::audit::append("docker-credential-setup", &json!({"registry": registry}))?;
    Ok(json!({"ok": true, "registry": registry, "program": program.display().to_string(), "config": file.display().to_string()}))
}

/// Docker's config.json and the registries it sends to this vault, so doctor
/// can check that the program they name is still there.
pub(crate) fn registries() -> Result<(PathBuf, Vec<String>)> {
    let file = config_file()?;
    let named = read_config(&file)?
        .get(HELPERS)
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(_, helper)| helper.as_str() == Some(HELPER))
        .map(|(registry, _)| registry.clone())
        .collect();
    Ok((file, named))
}

/// The registries config.json still keeps a base64 sign-in for under auths,
/// so doctor can name those Docker asks this vault for as well.
pub(crate) fn plain_auths() -> Result<Vec<String>> {
    let file = config_file()?;
    Ok(read_config(&file)?
        .get("auths")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(_, entry)| entry.get("auth").and_then(Value::as_str).is_some_and(|auth| !auth.is_empty()))
        .map(|(registry, _)| registry.clone())
        .collect())
}

/// The docker-credential-skarbiec Docker would run: the first on PATH, as
/// Docker looks it up, whether or not its link still leads anywhere.
pub(crate) fn program_on_path() -> Result<Option<PathBuf>> {
    let Some(path) = crate::core::env::text("PATH")? else {
        return Ok(None);
    };
    Ok(path
        .split(':')
        .map(|dir| Path::new(dir).join(PROGRAM))
        .find(|candidate| candidate.symlink_metadata().is_ok()))
}

pub(super) fn unset(registry: &str) -> Result<Value> {
    let registry = crate::runtime::gitcred::checked_host(registry)?;
    let file = config_file()?;
    let mut members = read_config(&file)?;
    let removed = members
        .get_mut(HELPERS)
        .and_then(Value::as_object_mut)
        .and_then(|helpers| helpers.remove(registry));
    if removed.is_none() {
        bail!("Docker's {} names no credential helper for {registry}; nothing was changed", file.display());
    }
    write_config(&file, members)?;
    crate::runtime::audit::append("docker-credential-unset", &json!({"registry": registry}))?;
    // The linked program stays: other registries may name it.
    Ok(json!({"ok": true, "registry": registry, "config": file.display().to_string()}))
}
