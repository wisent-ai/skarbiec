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
    let unsafe_bits = u32::from_str_radix("077", "8".parse()?)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()?
        || metadata.mode() & unsafe_bits != u32::MIN
    {
        bail!("workload public key must be an owner-controlled regular file");
    }
    let key = fs::read_to_string(path)?;
    let maximum: usize = "8192".parse()?;
    if key.is_empty()
        || key.len() > maximum
        || !key.contains("-----BEGIN PUBLIC KEY-----")
        || !key.contains("-----END PUBLIC KEY-----")
    {
        bail!("workload public key must be a bounded PEM public key");
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
    let unsafe_bits = u32::from_str_radix("077", "8".parse()?)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()?
        || metadata.mode() & unsafe_bits != u32::MIN
    {
        bail!("token file must be an owner-controlled regular file");
    }
    let contents = fs::read_to_string(path)?;
    let token = contents.trim_end_matches(['\r', '\n']);
    if token.is_empty() || token.len() > "4096".parse()? || token.chars().any(char::is_whitespace) {
        bail!("token file must contain one bounded non-whitespace token");
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

pub(in crate::access::grant) fn allowed_action(action: &str) -> bool {
    matches!(
        action,
        "acquire"
            | "read"
            | "stage"
            | "rotate"
            | "verify"
            | "revoke"
            | "share"
            | "trash"
            | "purge"
            | "admin"
            | "sync"
            | "enroll"
            | "donate"
            // Credential lifecycle: drive operations on one exact item, and
            // reseal its directory contract. Neither reads a value.
            | "lifecycle"
            | "reseal"
            // Ask what an inbound bearer is. Held by a gateway that has to
            // decide whether to serve a request, so that deciding does not
            // require keeping a copy of every credential in the fleet. Reads no
            // value: the answer is an identity and its capabilities.
            | "introspect"
            // Be called. The right to reach a service, and with `#field` the
            // exact route within it, so a client's reach is a grant here rather
            // than a list compiled into the service it calls.
            | "call"
    )
}

/// A route within a service: components joined by `/`, each one exact.
///
/// Separators are allowed because a route has them; nothing else is. No empty
/// component, so neither a leading nor a trailing slash nor `//`, and no `..`,
/// which is how a path pattern would otherwise reach outside what was granted.
pub(in crate::access::grant) fn exact_route(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= "128".parse().unwrap_or(usize::MAX)
        && value.split('/').all(exact_component)
        && !value.split('/').any(|component| component == "..")
}
