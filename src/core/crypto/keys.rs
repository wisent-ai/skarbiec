// The keyring: generating a key, finding a fingerprint, and telling whether
// the secret half of one is still on this machine.

use anyhow::{bail, Context, Result};

use super::execution::{run, ToolExit};

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
    let listing = match absent_as_none(
        run("gpg", &["--list-keys", "--with-colons", uid], None),
        "GPG_ERR_NO_PUBKEY",
    )? {
        Some(text) => text,
        None => return Ok(None),
    };
    Ok(listing
        .lines()
        .find_map(|line| hex_field(line, "fpr"))
        .map(str::to_string))
}

/// The hex value of a `--with-colons` record of `kind` (`fpr`, `grp`): its
/// first field that is non-empty and all hex digits, or `None` for a record
/// of another kind.
fn hex_field<'a>(line: &'a str, kind: &str) -> Option<&'a str> {
    line.strip_prefix(kind)?
        .split(':')
        .find(|field| !field.is_empty() && field.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Whether the private half for this fingerprint is in the local keyring. The
/// public half proves nothing: stored ciphertext opens only for whoever holds a
/// secret key, and a vault can list a recipient whose secret half is long gone.
pub fn secret_key_present(fingerprint: &str) -> Result<bool> {
    let listing = absent_as_none(
        run(
            "gpg",
            &["--list-secret-keys", "--with-colons", fingerprint],
            None,
        ),
        "GPG_ERR_NO_SECKEY",
    )?;
    Ok(listing.is_some_and(|listing| {
        listing
            .lines()
            .any(|line| line.starts_with("sec:") || line.starts_with("ssb:"))
    }))
}

/// Keygrips of a key and its subkeys. `gpg-agent` stores each secret half as
/// `private-keys-v1.d/<KEYGRIP>.key`, so these are the exact filenames a restore
/// from backup has to produce: the fingerprint names the key, the keygrip names
/// the file on disk.
pub fn keygrips_for(fingerprint: &str) -> Result<Vec<String>> {
    let listing = match absent_as_none(
        run(
            "gpg",
            &[
                "--list-keys",
                "--with-colons",
                "--with-keygrip",
                fingerprint,
            ],
            None,
        ),
        "GPG_ERR_NO_PUBKEY",
    )? {
        Some(text) => text,
        None => return Ok(Vec::new()),
    };
    let mut grips: Vec<String> = Vec::new();
    for grip in listing.lines().filter_map(|line| hex_field(line, "grp")) {
        if !grips.iter().any(|kept| kept == grip) {
            grips.push(grip.to_string());
        }
    }
    Ok(grips)
}

/// A gpg listing, or none when gpg refused it only because the key it was
/// asked for is not in the keyring: one of its status errors is the code
/// `absent` names in gpg-error.h. Any other failure (a wedged keyboxd, a held
/// keyring lock, a dead agent) is the error itself, so it is never read as a
/// key that is not there.
fn absent_as_none(listing: Result<String>, absent: &str) -> Result<Option<String>> {
    let error = match listing {
        Ok(text) => return Ok(Some(text)),
        Err(error) => error,
    };
    let exit = match error.downcast_ref::<ToolExit>() {
        Some(exit) => exit,
        None => return Err(error),
    };
    for value in &exit.gpg_errors {
        if gpg_error_names(*value)?.contains(&absent.to_string()) {
            return Ok(None);
        }
    }
    Err(error)
}

/// The names libgpg-error's own `gpg-error` tool gives a status value: its
/// answer is `<value> = (<source>, <code>) = (<SOURCE NAME>, <CODE NAME>) =
/// (<descriptions>)`, read word by word.
fn gpg_error_names(value: u32) -> Result<Vec<String>> {
    let output = stado_wait::output(std::process::Command::new("gpg-error").arg(value.to_string()))
        .with_context(|| format!("gpg-error could not be run to name gpg status value {value}"))?;
    if !output.status.success() {
        bail!(
            "gpg-error refused to name gpg status value {value} ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let answer = String::from_utf8(output.stdout).with_context(|| {
        format!("gpg-error named status value {value} in text that is not UTF-8")
    })?;
    Ok(answer
        .split([' ', '(', ')', ','])
        .filter(|word| !word.is_empty())
        .map(str::to_string)
        .collect())
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

/// The OpenPGP packet header of a public-key encrypted session key, and the
/// word before the recipient's key id in it, as `gpg --list-packets` prints
/// them (RFC 4880 section 5.1 names the packet).
const SESSION_KEY_PACKET: &str = ":pubkey enc packet:";
const KEY_ID_WORD: &str = "keyid ";

/// The key ids a message is encrypted to, read from its session key packets
/// without decrypting it (`--list-only`): what a message that will not open
/// was written for, to set beside the secret keys this keyring holds.
pub fn encrypted_to(ciphertext: &str) -> Result<Vec<String>> {
    let listing = run(
        "gpg",
        &["--batch", "--list-only", "--list-packets"],
        Some(ciphertext),
    )?;
    Ok(listing
        .lines()
        .filter(|line| line.starts_with(SESSION_KEY_PACKET))
        .filter_map(|line| line.rsplit_once(KEY_ID_WORD))
        .map(|(_, key_id)| key_id.trim().to_string())
        .collect())
}
