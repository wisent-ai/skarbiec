// The operator-supplied names, addresses and handles a command accepts, and
// the owner-only files bearer material is read from so it never enters argv.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::checks::uuid_shaped;
use super::lock::{effective_uid, exact_name};
use super::TOKEN_FILE_ENV;

pub(in crate::credential) fn lowercase_uuid(
    flag: &str,
    value: Option<&String>,
) -> Result<Option<String>> {
    let Some(value) = value.map(|value| value.trim().to_string()) else {
        return Ok(None);
    };
    if !uuid_shaped(&value)? {
        bail!("{flag} must be a lowercase 8-4-4-4-12 hexadecimal UUID");
    }
    Ok(Some(value))
}

pub(in crate::credential) fn email_address(
    flag: &str,
    value: Option<&String>,
) -> Result<Option<String>> {
    let Some(value) = value.map(|value| value.trim().to_lowercase()) else {
        return Ok(None);
    };
    let valid = value.len() <= 254
        && !value.chars().any(char::is_control)
        && value.split('@').count() == std::iter::once(()).count().saturating_add(1)
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
        });
    if !valid {
        bail!("{flag} must be one valid email address");
    }
    Ok(Some(value))
}

pub(in crate::credential) fn opaque_handle(name: &str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("{name} must be 1-{maximum} characters of ASCII letters, digits, '.', '_', or '-'");
    }
    Ok(())
}

// Bearer material is read from an owner-only file so it never appears in argv.
pub(crate) fn read_secret_file(path: &Path) -> Result<String> {
    if !path.is_absolute() {
        bail!("credential token file must be an absolute path");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect credential token file {}", path.display()))?;
    let unsafe_bits = 0o077;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid()?
        || metadata.permissions().mode() & unsafe_bits != u32::MIN
    {
        bail!("credential token file must be an owner-only regular file");
    }
    let max: usize = 512;
    let token = fs::read_to_string(path)?.trim().to_string();
    if token.is_empty() || token.len() > max || token.chars().any(char::is_control) {
        bail!("credential token file must hold exactly one bounded bearer token");
    }
    Ok(token)
}

/// The bearer `command` presents, read only from the owner-only file
/// `--token-file` names. `--token <value>` is refused: a value in argv is
/// readable by every process on the host and lands in shell history, so no
/// command takes one.
pub(crate) fn bearer_from_file(flags: &HashMap<String, String>, command: &str) -> Result<String> {
    if flags.contains_key("token") {
        bail!(
            "{command} does not take --token: a bearer in argv is readable by every process on this host. \
             Write it to an owner-only file (mode 0600) and pass --token-file <absolute path>"
        );
    }
    let path = flags.get("token-file").with_context(|| {
        format!("{command} requires --token-file <absolute path to an owner-only file holding the bearer>")
    })?;
    read_secret_file(Path::new(path.trim()))
}

pub(in crate::credential) fn client_identity(
    flags: &HashMap<String, String>,
) -> Result<(String, String)> {
    let consumer = flags
        .get("as")
        .or_else(|| flags.get("consumer"))
        .context("--as <consumer> is required to reach the canonical Skarbiec")?
        .clone();
    exact_name("consumer", &consumer, 200)?;
    let path = match flags.get("token-file") {
        Some(path) => PathBuf::from(path.trim()),
        None => {
            let configured = std::env::var(TOKEN_FILE_ENV)
                .ok()
                .filter(|path| !path.trim().is_empty())
                .with_context(|| {
                    format!("--token-file <path> or {TOKEN_FILE_ENV} is required to reach the canonical Skarbiec")
                })?;
            PathBuf::from(configured.trim())
        }
    };
    let token = read_secret_file(&path)?;
    Ok((consumer, token))
}

// The approval id is a handle; the resume token is capability material, so a
// file keeps it out of argv when the operator has somewhere to put it.
pub(in crate::credential) fn resume_handles(
    flags: &HashMap<String, String>,
) -> Result<(String, String)> {
    let approval_id = flags
        .get("approval")
        .context("--approval <id> is required")?
        .trim()
        .to_string();
    opaque_handle("--approval", &approval_id, 64)?;
    let resume_token = match flags.get("resume-token-file") {
        Some(path) => read_secret_file(Path::new(path.trim()))?,
        None => flags
            .get("resume-token")
            .context("--resume-token <token> or --resume-token-file <path> is required")?
            .trim()
            .to_string(),
    };
    opaque_handle("--resume-token", &resume_token, 128)?;
    Ok((approval_id, resume_token))
}
