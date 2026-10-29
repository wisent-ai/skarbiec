// `backup schedule <directory>` makes every `skarbiec maintain` pass on this
// host keep one rolling copy of the vault there, `<vault file name>.latest`,
// replaced only when the vault changed since; `backup unschedule` stops it.
// The directory is this host's choice — an external disk, a synced folder —
// so it is kept beside the vault file in `<vault file>.backup-directory`,
// never in the vault document, which replicas receive. The rolling copy is
// written owner-only beside its final name, synced, read back as a vault and
// only then renamed over the previous one, so a pass that fails leaves the
// last good copy in place.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::cli::args::Usage;
use crate::core::{vault::Vault, vault_path};

/// Where this host's schedule is kept: beside the vault file it backs up.
fn marker(vault: &Path) -> PathBuf {
    let mut name = vault.as_os_str().to_owned();
    name.push(".backup-directory");
    PathBuf::from(name)
}

fn rolling_name(vault: &Path) -> Result<String> {
    match vault.file_name() {
        Some(name) => Ok(format!("{}.latest", name.to_string_lossy())),
        None => bail!("the vault path {} names no file", vault.display()),
    }
}

pub(super) fn schedule(directory: &Path) -> Result<Value> {
    if !directory.is_absolute() {
        return Err(Usage(format!(
            "backup schedule takes an absolute directory, not {}: maintain runs from wherever its schedule starts it",
            directory.display()
        ))
        .into());
    }
    if !crate::core::file_type(directory, "the backup directory")?.is_some_and(|kind| kind.is_dir())
    {
        bail!(
            "{} is not a directory here; nothing was scheduled",
            directory.display()
        );
    }
    let vault = vault_path();
    Vault::open(vault.clone())?;
    let path = marker(&vault);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(crate::core::vault::private_file_mode()?)
        .open(&path)
        .with_context(|| format!("write the backup schedule {}", path.display()))?;
    file.write_all(directory.as_os_str().as_encoded_bytes())
        .with_context(|| format!("write the backup schedule {}", path.display()))?;
    file.sync_all()?;
    crate::runtime::audit::append(
        "backup-scheduled",
        &json!({"directory": directory.display().to_string()}),
    )?;
    Ok(json!({
        "ok": true,
        "directory": directory.display().to_string(),
        "copy": directory.join(rolling_name(&vault)?).display().to_string(),
    }))
}

pub(super) fn unschedule() -> Result<Value> {
    let path = marker(&vault_path());
    let removed = match std::fs::remove_file(&path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("remove the backup schedule {}", path.display()))
        }
    };
    if removed {
        crate::runtime::audit::append("backup-unscheduled", &json!({}))?;
    }
    Ok(json!({"ok": true, "unscheduled": removed}))
}

/// `backup schedule` alone: the directory this host backs up to and the
/// rolling copy's path, or null when it backs up nowhere.
pub(super) fn current() -> Result<Value> {
    let vault = vault_path();
    match scheduled_directory(&vault)? {
        None => Ok(json!({"ok": true, "directory": null, "copy": null})),
        Some(directory) => Ok(json!({
            "ok": true,
            "directory": directory.display().to_string(),
            "copy": directory.join(rolling_name(&vault)?).display().to_string(),
        })),
    }
}

/// The directory this host backs up to, when it does.
pub(super) fn scheduled_directory(vault: &Path) -> Result<Option<PathBuf>> {
    let path = marker(vault);
    match crate::core::read_present(&path, "backup schedule")? {
        None => Ok(None),
        Some(text) if text.trim().is_empty() => {
            bail!("the backup schedule {} names no directory", path.display())
        }
        Some(text) => Ok(Some(PathBuf::from(text.trim()))),
    }
}

/// One maintain step: `None` when this host schedules no backup; otherwise
/// the rolling copy, refreshed when the vault differs from it.
pub fn scheduled_pass() -> Result<Option<Value>> {
    let vault = vault_path();
    let Some(directory) = scheduled_directory(&vault)? else {
        return Ok(None);
    };
    if !crate::core::file_type(&directory, "the scheduled backup directory")?
        .is_some_and(|kind| kind.is_dir())
    {
        bail!(
            "the scheduled backup directory {} is not there — a disk unplugged, a folder moved; \
             reconnect it, or `skarbiec backup schedule <directory>` names another",
            directory.display()
        );
    }
    let target = directory.join(rolling_name(&vault)?);
    let current = std::fs::read(&vault)
        .with_context(|| format!("read the vault file {}", vault.display()))?;
    match std::fs::read(&target) {
        Ok(kept) if kept == current => {
            return Ok(Some(
                json!({"copy": target.display().to_string(), "refreshed": false}),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read the rolling backup {}", target.display()))
        }
    }
    let staged = directory.join(format!("{}.writing", rolling_name(&vault)?));
    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(crate::core::vault::private_file_mode()?)
        .open(&staged)
        .with_context(|| format!("create {}", staged.display()))?;
    output
        .write_all(&current)
        .with_context(|| format!("write {}", staged.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync {}", staged.display()))?;
    Vault::open(staged.clone()).with_context(|| {
        format!(
            "{} does not read back as a vault; the last copy is kept",
            staged.display()
        )
    })?;
    std::fs::rename(&staged, &target)
        .with_context(|| format!("put {} in place of {}", staged.display(), target.display()))?;
    crate::runtime::audit::append(
        "vault-backed-up",
        &json!({"backup": target.display().to_string(), "bytes": current.len(), "scheduled": true}),
    )?;
    Ok(Some(
        json!({"copy": target.display().to_string(), "refreshed": true}),
    ))
}
