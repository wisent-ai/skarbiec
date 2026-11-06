// What a grant is allowed to name, and how the two files it may read are
// checked before anything in them is believed.

use anyhow::{bail, Context, Result};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::core::effective_uid;

/// Whether a group or another user holds any permission on a file: an
/// owner-controlled file holds none.
fn shared_beyond_owner(metadata: &fs::Metadata) -> bool {
    (metadata.mode() & crate::core::mode::GROUP_AND_OTHER) != 0
}

pub(in crate::access::grant) fn read_workload_public_key(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()
        || shared_beyond_owner(&metadata)
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
    // The same reader that verifies the key's proofs judges the key, so a
    // key accepted here is one every proof is checked against.
    crate::core::crypto::signature::ed25519_public_key(&key)
        .with_context(|| format!("workload public key {}", path.display()))?;
    Ok(key)
}

pub(in crate::access::grant) fn read_fixed_token(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()
        || shared_beyond_owner(&metadata)
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
