// One credential operation at a time on one vault, and the clock and names
// every operation is written with.

use anyhow::{bail, Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(in crate::credential) struct CredentialOperationLock(PathBuf);

impl Drop for CredentialOperationLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}


pub(in crate::credential) fn acquire_credential_operation_lock(
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

pub(in crate::credential) fn now_iso() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

pub(in crate::credential) fn exact_name(name: &str, value: &str, maximum: usize) -> Result<()> {
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

pub(in crate::credential) fn purpose(value: Option<&String>, consumer: &str) -> Result<String> {
    let value = value.map(String::as_str).unwrap_or(consumer);
    let max: usize = "200".parse()?;
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        bail!("purpose must be 1-200 printable UTF-8 bytes");
    }
    Ok(value.to_string())
}

pub(in crate::credential) fn effective_uid() -> Result<u32> {
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
