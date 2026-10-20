// One credential operation at a time on one vault, and the clock and names
// every operation is written with.

use anyhow::{bail, Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

pub(in crate::credential) struct CredentialOperationLock(PathBuf);

impl Drop for CredentialOperationLock {
    fn drop(&mut self) {
        crate::core::staging::remove_said(&self.0, "the credential operation lock is not released");
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
    crate::core::clock::now_iso()
}

pub(in crate::credential) fn exact_name(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
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
    if value.is_empty() || value.chars().any(char::is_control) {
        bail!("purpose must be non-empty printable UTF-8");
    }
    Ok(value.to_string())
}
