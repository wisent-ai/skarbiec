use anyhow::{bail, Context, Result};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const MAX_VALUE_FILE_BYTES: u64 = 16 * 1024;

/// Reads a scalar secret from an already-provisioned owner-only file.
///
/// Validation is performed on the opened descriptor so replacing the path
/// between open and inspection cannot bypass the file type, owner, mode, or
/// size checks. `O_NONBLOCK` prevents a non-regular file from stalling open;
/// such a descriptor is rejected immediately after opening.
pub fn read_value_file(path: &Path) -> Result<String> {
    if !path.is_absolute() {
        bail!("--value-file must be an absolute path");
    }

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open --value-file")?;
    let metadata = file.metadata().context("inspect --value-file")?;

    if !metadata.is_file() {
        bail!("--value-file must be a regular file");
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!("--value-file must be owned by the effective user");
    }
    if metadata.permissions().mode() & 0o177 != 0 {
        bail!("--value-file permissions must be 0600 or stricter");
    }
    if metadata.len() > MAX_VALUE_FILE_BYTES {
        bail!("value file exceeds 16384-byte limit");
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_VALUE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read --value-file")?;
    if bytes.len() as u64 > MAX_VALUE_FILE_BYTES {
        bail!("value file exceeds 16384-byte limit");
    }

    let mut value = String::from_utf8(bytes).context("--value-file must contain UTF-8")?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    Ok(value)
}
