// The keyring: generating a key, finding a fingerprint, and telling whether
// the secret half of one is still on this machine.

use anyhow::{Context, Result};

use super::execution::{run, run_opt};

/// Generate a new key pair for a user id, returning its fingerprint.
pub fn generate_key(uid: &str) -> Result<String> {
    run(
        "gpg",
        &[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            uid,
            "default",
            "default",
            "never",
        ],
        None,
    )?;
    fingerprint_for(uid)?.with_context(|| format!("key not found after generating for {uid}"))
}

/// Fingerprint of a key already in the local keyring for this user id, if any.
pub fn fingerprint_for(uid: &str) -> Result<Option<String>> {
    let listing = match run_opt("gpg", &["--list-keys", "--with-colons", uid], None) {
        Some(text) => text,
        None => return Ok(None),
    };
    for line in listing.lines() {
        if let Some(rest) = line.strip_prefix("fpr") {
            if let Some(fpr) = rest
                .split(':')
                .find(|field| !field.is_empty() && field.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return Ok(Some(fpr.to_string()));
            }
        }
    }
    Ok(None)
}

/// Whether the private half for this fingerprint is in the local keyring. The
/// public half proves nothing: stored ciphertext opens only for whoever holds a
/// secret key, and a vault can list a recipient whose secret half is long gone.
pub fn secret_key_present(fingerprint: &str) -> bool {
    let listing = match run_opt(
        "gpg",
        &["--list-secret-keys", "--with-colons", fingerprint],
        None,
    ) {
        Some(text) => text,
        None => return false,
    };
    listing
        .lines()
        .any(|line| line.starts_with("sec:") || line.starts_with("ssb:"))
}

/// Keygrips of a key and its subkeys. `gpg-agent` stores each secret half as
/// `private-keys-v1.d/<KEYGRIP>.key`, so these are the exact filenames a restore
/// from backup has to produce: the fingerprint names the key, the keygrip names
/// the file on disk.
pub fn keygrips_for(fingerprint: &str) -> Vec<String> {
    let listing = match run_opt(
        "gpg",
        &[
            "--list-keys",
            "--with-colons",
            "--with-keygrip",
            fingerprint,
        ],
        None,
    ) {
        Some(text) => text,
        None => return Vec::new(),
    };
    let mut grips: Vec<String> = Vec::new();
    for line in listing.lines() {
        if let Some(rest) = line.strip_prefix("grp") {
            if let Some(found) = rest
                .split(':')
                .find(|field| !field.is_empty() && field.chars().all(|c| c.is_ascii_hexdigit()))
            {
                let grip = found.to_string();
                if !grips.contains(&grip) {
                    grips.push(grip);
                }
            }
        }
    }
    grips
}

/// Import an armored public (or private) key, returning nothing on success.
pub fn import_key(armored: &str) -> Result<()> {
    run("gpg", &["--batch", "--import"], Some(armored))?;
    Ok(())
}

/// Export a recipient's armored public key for sharing the vault.
pub fn export_public_key(fingerprint: &str) -> Result<String> {
    run("gpg", &["--armor", "--export", fingerprint], None)
}
