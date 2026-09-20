// What the vault does with a message: encrypt it to recipients, decrypt it
// with whatever unlock the operator configured, sign it, and hash it.

use anyhow::{bail, Context, Result};

use super::execution::run;

pub fn clearsign(signer: &str, payload: &str) -> Result<String> {
    run(
        "gpg",
        &[
            "--batch",
            "--yes",
            "--armor",
            "--local-user",
            signer,
            "--clearsign",
        ],
        Some(payload),
    )
}

pub fn verify_clearsigned(signed: &str) -> Result<String> {
    run("gpg", &["--batch", "--yes", "--decrypt"], Some(signed))
}

/// High-entropy random token (hex). Used for consumer service tokens.
///
/// `/dev/urandom` rather than `openssl rand`: minting a token used to spawn a
/// process that queued behind live decryptions in the shared crypto pool, and
/// a token is minted on paths that hold no secret at all.
pub fn random_token() -> Result<String> {
    use std::io::Read;
    let mut bytes = [u8::MIN; 32];
    std::fs::File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut bytes)
        .context("read entropy for a service token")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Hex SHA-256 of the input. Used by the tamper-evident audit chain and the
/// breach k-anonymity check.
///
/// In process, because this is how a bearer is verified on EVERY
/// authenticated route. As a `shasum` child it took a slot in the same
/// bounded pool the gpg decryptions use, so a request that hashes one string
/// waited behind work it has nothing to do with: on 2026-09-05 a grant
/// metadata call took 14.4s and `GET /readyz` 9.7s for exactly that reason,
/// and verifying a 74,859-line audit chain cost one process per line.
pub fn sha256_hex(input: &str) -> Result<String> {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(input.as_bytes());
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// SHA-1 (uppercase hex) — required only for the HaveIBeenPwned range API, which
/// is defined over SHA-1 password hashes. Not used for any security decision.
pub fn sha1_hex_upper(input: &str) -> Result<String> {
    use sha1::Digest;
    let digest = sha1::Sha1::digest(input.as_bytes());
    Ok(digest.iter().map(|byte| format!("{byte:02X}")).collect())
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
/// for a single invocation, an owner-only file named by
/// `SKARBIEC_UNLOCK_FILE`, or the persistent service default
/// `$HOME/.stado/skarbiec-unlock`. The phrase is handed to gpg over stdin,
/// never argv. With no phrase, an unprotected key decrypts normally while a
/// protected key fails without opening an interactive prompt.
fn unlock_phrase() -> Result<Option<String>> {
    if let Ok(phrase) = std::env::var("SKARBIEC_UNLOCK") {
        if !phrase.is_empty() {
            return Ok(Some(phrase));
        }
    }
    let path = match std::env::var("SKARBIEC_UNLOCK_FILE") {
        Ok(path) if !path.trim().is_empty() => std::path::PathBuf::from(path),
        _ => {
            let Some(home) = std::env::var_os("HOME") else {
                return Ok(None);
            };
            let candidate = std::path::PathBuf::from(home)
                .join(".stado")
                .join("skarbiec-unlock");
            if !candidate.is_file() {
                return Ok(None);
            }
            candidate
        }
    };
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("inspect Skarbiec unlock file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            anyhow::bail!(
                "Skarbiec unlock file {} must be a regular file",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("Skarbiec unlock file {} must be mode 0600", path.display());
        }
    }
    let phrase = std::fs::read_to_string(&path)
        .with_context(|| format!("read Skarbiec unlock file {}", path.display()))?;
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
