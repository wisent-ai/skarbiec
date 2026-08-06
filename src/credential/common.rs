// Value checks shared by every credential path, the operator-supplied flags and
// owner-only files a command reads before it acts, and the single-writer lock a
// credential operation holds while it owns the vault file.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) struct CredentialOperationLock(PathBuf);

impl Drop for CredentialOperationLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub(super) const TOKEN_FILE_ENV: &str = "SKARBIEC_CREDENTIAL_TOKEN_FILE";

pub(super) fn acquire_credential_operation_lock(
    vault_path: &Path,
) -> Result<CredentialOperationLock> {
    let lock_path = vault_path.with_extension("credential-operation.lock");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .with_context(|| {
            format!(
                "another credential operation owns {}; if its process crashed, verify no Weles task is active before removing the lock",
                lock_path.display()
            )
        })?;
    let guard = CredentialOperationLock(lock_path);
    writeln!(file, "{}", std::process::id())?;
    Ok(guard)
}

pub(super) fn now_iso() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

pub(super) fn exact_name(name: &str, value: &str, maximum: usize) -> Result<()> {
    let max = maximum;
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("{name} must contain only ASCII letters, digits, '.', '_', or '-'");
    }
    Ok(())
}

pub(super) fn purpose(value: Option<&String>, consumer: &str) -> Result<String> {
    let value = value.map(String::as_str).unwrap_or(consumer);
    let max: usize = "200".parse()?;
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        bail!("purpose must be 1-200 printable UTF-8 bytes");
    }
    Ok(value.to_string())
}

pub(super) fn effective_uid() -> Result<u32> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("read effective uid")?;
    if !output.status.success() {
        bail!("could not determine effective uid");
    }
    String::from_utf8(output.stdout)?
        .trim()
        .parse()
        .context("parse effective uid")
}

pub(super) fn safe_string(value: &Value, key: &str) -> Option<String> {
    let max: usize = "512".parse().ok()?;
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| text.len() <= max && !text.chars().any(char::is_control))
        .map(str::to_string)
}

pub(super) fn present(value: &Value, key: &str) -> bool {
    value.get(key).is_some_and(|found| !found.is_null())
}

pub(super) fn checked_enum(value: &Value, key: &str, allowed: &[&str]) -> Result<Option<String>> {
    if !present(value, key) {
        return Ok(None);
    }
    let text = safe_string(value, key)
        .filter(|text| allowed.contains(&text.as_str()))
        .with_context(|| format!("Weles response {key} is not an accepted value"))?;
    Ok(Some(text))
}

pub(super) fn checked_bool(value: &Value, key: &str) -> Result<Option<bool>> {
    if !present(value, key) {
        return Ok(None);
    }
    let flag = value
        .get(key)
        .and_then(Value::as_bool)
        .with_context(|| format!("Weles response {key} must be a boolean"))?;
    Ok(Some(flag))
}

pub(super) fn checked_code(value: &Value) -> Result<Option<String>> {
    if !present(value, "code") {
        return Ok(None);
    }
    let text = safe_string(value, "code").context("Weles response code is not a bounded string")?;
    let max: usize = "64".parse()?;
    let shaped = text.len() <= max
        && text.starts_with(|first: char| first.is_ascii_uppercase())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
    if !shaped {
        bail!("Weles response code must be an uppercase machine-readable identifier");
    }
    Ok(Some(text))
}

pub(super) fn checked_host(value: &Value) -> Result<Option<String>> {
    if !present(value, "executionHost") {
        return Ok(None);
    }
    let max: usize = "128".parse()?;
    let host = safe_string(value, "executionHost")
        .filter(|host| !host.is_empty() && host.len() <= max)
        .context("Weles response executionHost must be a bounded single-line host name")?;
    Ok(Some(host))
}

pub(super) fn checked_uuid(value: &Value, key: &str) -> Result<Option<String>> {
    if !present(value, key) {
        return Ok(None);
    }
    let text =
        safe_string(value, key).with_context(|| format!("Weles response {key} is not a string"))?;
    if !uuid_shaped(&text)? {
        bail!("Weles response {key} must be a lowercase 8-4-4-4-12 hexadecimal UUID");
    }
    Ok(Some(text))
}

pub(super) fn hex_digest(value: &str) -> Result<bool> {
    let width: usize = "64".parse()?;
    Ok(value.len() == width && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

// The only timestamp shape Skarbiec writes or accepts: zulu seconds, with an
// optional fraction, so two stamps compare as text.
pub(super) fn timestamp_shaped(value: &str) -> bool {
    let Some((date, rest)) = value.split_once('T') else {
        return false;
    };
    let Some(time) = rest.strip_suffix('Z') else {
        return false;
    };
    let (clock, fraction) = match time.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (time, None),
    };
    let date_widths = ["4", "2", "2"];
    let clock_widths = ["2", "2", "2"];
    let date_groups: Vec<&str> = date.split('-').collect();
    let clock_groups: Vec<&str> = clock.split(':').collect();
    let digits = |group: &&str, width: &&str| {
        width
            .parse::<usize>()
            .is_ok_and(|width| group.len() == width)
            && group.bytes().all(|byte| byte.is_ascii_digit())
    };
    let fraction_max: usize = "6".parse().unwrap_or_default();
    date_groups.len() == date_widths.len()
        && clock_groups.len() == clock_widths.len()
        && date_groups
            .iter()
            .zip(date_widths.iter())
            .all(|(group, width)| digits(group, width))
        && clock_groups
            .iter()
            .zip(clock_widths.iter())
            .all(|(group, width)| digits(group, width))
        && fraction.is_none_or(|fraction| {
            !fraction.is_empty()
                && fraction.len() <= fraction_max
                && fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
}

pub(super) fn checked_timestamp(value: &Value, key: &str) -> Result<Option<String>> {
    if !present(value, key) {
        return Ok(None);
    }
    let text = safe_string(value, key)
        .filter(|text| timestamp_shaped(text))
        .with_context(|| format!("Weles response {key} must be an ISO 8601 zulu timestamp"))?;
    Ok(Some(text))
}

pub(super) fn zulu_seconds(value: &str) -> String {
    value
        .trim_end_matches('Z')
        .split('.')
        .next()
        .unwrap_or_default()
        .to_string()
}

pub(super) fn uuid_shaped(value: &str) -> Result<bool> {
    let expected = ["8", "4", "4", "4", "12"];
    let groups: Vec<&str> = value.split('-').collect();
    Ok(groups.len() == expected.len()
        && groups.iter().zip(expected.iter()).all(|(group, width)| {
            width
                .parse::<usize>()
                .is_ok_and(|width| group.len() == width)
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        }))
}

pub(super) fn lowercase_uuid(flag: &str, value: Option<&String>) -> Result<Option<String>> {
    let Some(value) = value.map(|value| value.trim().to_string()) else {
        return Ok(None);
    };
    if !uuid_shaped(&value)? {
        bail!("{flag} must be a lowercase 8-4-4-4-12 hexadecimal UUID");
    }
    Ok(Some(value))
}

pub(super) fn email_address(flag: &str, value: Option<&String>) -> Result<Option<String>> {
    let Some(value) = value.map(|value| value.trim().to_lowercase()) else {
        return Ok(None);
    };
    let valid = value.len() <= "254".parse()?
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

pub(super) fn opaque_handle(name: &str, value: &str, maximum: usize) -> Result<()> {
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
pub(super) fn read_secret_file(path: &Path) -> Result<String> {
    if !path.is_absolute() {
        bail!("credential token file must be an absolute path");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect credential token file {}", path.display()))?;
    let unsafe_bits = u32::from_str_radix("077", "8".parse()?)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid()?
        || metadata.permissions().mode() & unsafe_bits != u32::MIN
    {
        bail!("credential token file must be an owner-only regular file");
    }
    let max: usize = "512".parse()?;
    let token = fs::read_to_string(path)?.trim().to_string();
    if token.is_empty() || token.len() > max || token.chars().any(char::is_control) {
        bail!("credential token file must hold exactly one bounded bearer token");
    }
    Ok(token)
}

pub(super) fn client_identity(flags: &HashMap<String, String>) -> Result<(String, String)> {
    let consumer = flags
        .get("as")
        .or_else(|| flags.get("consumer"))
        .context("--as <consumer> is required to reach the canonical Skarbiec")?
        .clone();
    exact_name("consumer", &consumer, "200".parse()?)?;
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
pub(super) fn resume_handles(flags: &HashMap<String, String>) -> Result<(String, String)> {
    let approval_id = flags
        .get("approval")
        .context("--approval <id> is required")?
        .trim()
        .to_string();
    opaque_handle("--approval", &approval_id, "64".parse()?)?;
    let resume_token = match flags.get("resume-token-file") {
        Some(path) => read_secret_file(Path::new(path.trim()))?,
        None => flags
            .get("resume-token")
            .context("--resume-token <token> or --resume-token-file <path> is required")?
            .trim()
            .to_string(),
    };
    opaque_handle("--resume-token", &resume_token, "128".parse()?)?;
    Ok((approval_id, resume_token))
}
