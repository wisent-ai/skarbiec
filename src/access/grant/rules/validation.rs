// What a grant is allowed to name, and how the two files it may read are
// checked before anything in them is believed.

use anyhow::{bail, Context, Result};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

pub(in crate::access::grant) fn effective_uid() -> Result<u32> {
    let output = Command::new("id").arg("-u").output()?;
    if !output.status.success() {
        bail!("could not determine effective uid");
    }
    String::from_utf8(output.stdout)?
        .trim()
        .parse()
        .context("parse effective uid")
}

pub(in crate::access::grant) fn read_workload_public_key(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    let unsafe_bits = 0o077;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()?
        || metadata.mode() & unsafe_bits != u32::MIN
    {
        bail!("workload public key must be an owner-controlled regular file");
    }
    let key = fs::read_to_string(path)?;
    if key.is_empty()
        || !key.contains("-----BEGIN PUBLIC KEY-----")
        || !key.contains("-----END PUBLIC KEY-----")
    {
        bail!("workload public key must be a PEM public key");
    }
    let output = Command::new("openssl")
        .args(["pkey", "-pubin", "-in"])
        .arg(path)
        .args(["-text_pub", "-noout"])
        .output()
        .context("validate workload public key with openssl")?;
    let description = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || !description.to_ascii_uppercase().contains("ED25519") {
        bail!("workload public key must be a valid Ed25519 public key");
    }
    Ok(key)
}

pub(in crate::access::grant) fn read_fixed_token(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    let unsafe_bits = 0o077;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()?
        || metadata.mode() & unsafe_bits != u32::MIN
    {
        bail!("token file must be an owner-controlled regular file");
    }
    let contents = fs::read_to_string(path)?;
    let token = contents.trim_end_matches(['\r', '\n']);
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        bail!("token file must contain one non-whitespace token");
    }
    Ok(token.to_string())
}

pub(in crate::access::grant) fn exact_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub(in crate::access::grant) fn exact_resource(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

/// A route within a service: components joined by `/`, each one exact.
///
/// Separators are allowed because a route has them; nothing else is. No empty
/// component, so neither a leading nor a trailing slash nor `//`, and no `..`,
/// which is how a path pattern would otherwise reach outside what was granted.
pub(in crate::access::grant) fn exact_route(value: &str) -> bool {
    !value.is_empty()
        && value.split('/').all(exact_component)
        && !value.split('/').any(|component| component == "..")
}
