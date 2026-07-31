// Cryptographic operations for the skarbiec vault, delegated to vetted local
// tools — never hand-rolled:
//   gpg     : per-recipient public-key authenticated encryption + key material
//   openssl : entropy (random tokens)
//   shasum  : hashing (audit chain, breach k-anonymity)
//   oathtool: optional time-based one-time codes
// The per-recipient model (encrypt to each recipient's public key) is the same
// shape 1Password/Bitwarden use for sharing.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};

// Run a program, optionally piping `input` to stdin. A nonzero exit is an error
// carrying stderr — the failure surfaces, never a silent empty result.
fn run(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {program}"))?;
    if let Some(text) = input {
        child
            .stdin
            .take()
            .context("child stdin unavailable")?
            .write_all(text.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// Probe variant for optional tools / trial key operations: a nonzero exit means
// "this key/tool did not apply" (a normal negative), returned as None.
fn run_opt(program: &str, args: &[&str], input: Option<&str>) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(text) = input {
        child.stdin.take()?.write_all(text.as_bytes()).ok()?;
    }
    let out = child.wait_with_output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

/// High-entropy random token (hex). Used for consumer service tokens.
pub fn random_token() -> Result<String> {
    Ok(run("openssl", &["rand", "-hex", "32"], None)?
        .trim()
        .to_string())
}

/// Hex SHA-256 of the input. Used by the tamper-evident audit chain and the
/// breach k-anonymity check.
pub fn sha256_hex(input: &str) -> Result<String> {
    let out = run("shasum", &["-a", "256", "-"], Some(input))?;
    out.split_whitespace()
        .next()
        .map(str::to_string)
        .context("empty sha256 output")
}

/// SHA-1 (uppercase hex) — required only for the HaveIBeenPwned range API, which
/// is defined over SHA-1 password hashes. Not used for any security decision.
pub fn sha1_hex_upper(input: &str) -> Result<String> {
    let out = run("shasum", &["-a", "1", "-"], Some(input))?;
    out.split_whitespace()
        .next()
        .map(|h| h.to_uppercase())
        .context("empty sha1 output")
}

/// Encrypt plaintext to every recipient's public key (armored). Any recipient
/// (or the recovery key) can later decrypt. This is how sharing works: add a
/// recipient and the item re-encrypts to include them.
pub fn encrypt_to(recipients: &[String], plaintext: &str) -> Result<String> {
    if recipients.is_empty() {
        bail!("refusing to encrypt with no recipients");
    }
    let mut args: Vec<String> = vec![
        "--batch".into(),
        "--yes".into(),
        "--armor".into(),
        "--trust-model".into(),
        "always".into(),
        "--encrypt".into(),
    ];
    for recipient in recipients {
        args.push("--recipient".into());
        args.push(recipient.clone());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run("gpg", &refs, Some(plaintext))
}

/// Decrypt using whatever private key in the local keyring applies (gpg-agent).
/// A protected vault can receive its unlock phrase through `SKARBIEC_UNLOCK`
/// for a single invocation or an owner-only file named by
/// `SKARBIEC_UNLOCK_FILE` for a persistent service. The phrase is handed to
/// gpg over stdin, never argv. With neither source, an unprotected key decrypts
/// normally while a protected key fails without opening an interactive prompt.
fn unlock_phrase() -> Result<Option<String>> {
    if let Ok(phrase) = std::env::var("SKARBIEC_UNLOCK") {
        if !phrase.is_empty() {
            return Ok(Some(phrase));
        }
    }
    let Ok(path) = std::env::var("SKARBIEC_UNLOCK_FILE") else {
        return Ok(None);
    };
    if path.trim().is_empty() {
        return Ok(None);
    }
    let phrase = std::fs::read_to_string(&path)
        .with_context(|| format!("read Skarbiec unlock file {path}"))?;
    let phrase = phrase.trim_end().to_string();
    Ok((!phrase.is_empty()).then_some(phrase))
}

pub fn decrypt(ciphertext: &str) -> Result<String> {
    match unlock_phrase()? {
        Some(phrase) => decrypt_protected(ciphertext, &phrase),
        _ => run(
            "gpg",
            &[
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--decrypt",
            ],
            Some(ciphertext),
        ),
    }
}

// Protected-key path: stage the ciphertext to a temp file and feed the phrase
// to gpg over stdin. The temp name gets a per-call sequence: a pid-only name
// let threaded decrypts swap each other's input file.
static TEMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MIN);

fn decrypt_protected(ciphertext: &str, phrase: &str) -> Result<String> {
    let mut path = std::env::temp_dir();
    let one = std::iter::once(()).count() as u64;
    path.push(format!(
        "skarbiec-ct-{}-{}.asc",
        std::process::id(),
        TEMP_SEQ.fetch_add(one, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&path, ciphertext).context("stage ciphertext")?;
    let file = path.to_string_lossy().into_owned();
    let out = run(
        "gpg",
        &[
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            "0",
            "--decrypt",
            &file,
        ],
        Some(phrase),
    );
    let _ = std::fs::remove_file(&path);
    out
}

#[allow(dead_code)] // public API surface consumed by the HTTP layer / clients
/// True when the local keyring (plus any SKARBIEC_UNLOCK) opens this
/// ciphertext. Used to gate reads by possession.
pub fn can_decrypt(ciphertext: &str) -> bool {
    decrypt(ciphertext).is_ok()
}

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

/// Current time-based one-time code for a base32 seed, when the standard oath
/// toolkit is installed. None means "install oath-toolkit to compute codes"; the
/// seed itself is still stored and emitted for the consumer.
pub fn totp_code(secret_base32: &str) -> Option<String> {
    run_opt("oathtool", &["--totp", "--base32", secret_base32], None)
        .map(|code| code.trim().to_string())
}
