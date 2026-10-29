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

/// The bytes of entropy in a consumer service token, which so carries 256
/// bits, above the 2^-160 guessing bound RFC 6749 sets for access tokens,
/// https://www.rfc-editor.org/rfc/rfc6749#section-10.10
const TOKEN_BYTES: usize = 32;

/// High-entropy random token (hex). Used for consumer service tokens.
///
/// `/dev/urandom` rather than `openssl rand`: minting a token used to spawn a
/// process that queued behind live decryptions in the shared crypto pool, and
/// a token is minted on paths that hold no secret at all.
pub fn random_token() -> Result<String> {
    use std::io::Read;
    let mut bytes = Vec::with_capacity(TOKEN_BYTES);
    std::fs::File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .take(u64::try_from(TOKEN_BYTES).context("the token length does not fit a read length")?)
        .read_to_end(&mut bytes)
        .context("read entropy for a service token")?;
    if bytes.len() != TOKEN_BYTES {
        bail!(
            "/dev/urandom ended after {} of the {TOKEN_BYTES} bytes a service token needs",
            bytes.len()
        );
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Hex SHA-256 of the input. Used by the tamper-evident audit chain and the
/// breach k-anonymity check.
///
/// In process, because this is how a bearer is verified on EVERY
/// authenticated route. As a `shasum` child it took a slot in the same
/// bounded pool the gpg decryptions use, so a request that hashes one string
/// waited behind work it has nothing to do with: a grant metadata call took
/// over ten seconds and `GET /readyz` nearly as long for exactly that
/// reason, and verifying a long audit chain cost one process per line.
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

/// Seal plaintext with a passphrase instead of a key (armored, symmetric):
/// for a person outside the vault, who opens it with `gpg --decrypt` and the
/// phrase handed over another way. The phrase travels on stdin before the
/// message, as the protected decrypt hands its phrase over, never in argv.
pub fn seal_with_passphrase(phrase: &str, plaintext: &str) -> Result<String> {
    if phrase.contains('\n') {
        bail!("a sealing passphrase holds a line break; gpg reads a phrase only up to its first line break");
    }
    let stdin = libc::STDIN_FILENO.to_string();
    run(
        "gpg",
        &[
            "--batch",
            "--yes",
            "--armor",
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            &stdin,
            "--symmetric",
        ],
        Some(&format!("{phrase}\n{plaintext}")),
    )
}

/// Decrypt using whatever private key in the local keyring applies (gpg-agent).
/// A protected vault can receive its unlock phrase through `SKARBIEC_UNLOCK`
/// for a single invocation, an owner-only file named by
/// `SKARBIEC_UNLOCK_FILE`, or the persistent service default
/// `$HOME/.stado/skarbiec-unlock`. The phrase is handed to gpg over stdin,
/// never argv. With no phrase, an unprotected key decrypts normally while a
/// protected key fails without opening an interactive prompt.
fn unlock_phrase() -> Result<Option<String>> {
    if let Some(phrase) = crate::core::env::text("SKARBIEC_UNLOCK")? {
        return Ok(Some(phrase));
    }
    let path = match crate::core::env::path("SKARBIEC_UNLOCK_FILE") {
        Some(path) => path,
        None => {
            let Some(home) = std::env::var_os("HOME") else {
                return Ok(None);
            };
            let candidate = std::path::PathBuf::from(home)
                .join(".stado")
                .join("skarbiec-unlock");
            // Only a default file that does not exist means "no phrase"; one
            // that cannot be inspected is reported below with its cause.
            match std::fs::symlink_metadata(&candidate) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                _ => candidate,
            }
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
        // Only the owner may read or write it: any permission bit outside
        // owner read and write refuses the file.
        let owner = crate::core::mode::OWNER_READ_WRITE;
        let access = metadata.permissions().mode() & crate::core::mode::ALL;
        if access | owner != owner {
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

// Protected-key path: gpg reads the phrase from its standard input one byte
// at a time up to the first newline (`--passphrase-fd`), and the message from
// the rest of the same input, so nothing is staged on disk and the phrase
// never reaches argv. A phrase holding a newline would end early and hand the
// rest of it to gpg as the message, so it is refused.
fn decrypt_protected(ciphertext: &str, phrase: &str) -> Result<String> {
    if phrase.contains('\n') {
        bail!("the Skarbiec unlock phrase holds a line break; gpg reads a phrase only up to its first line break");
    }
    let stdin = libc::STDIN_FILENO.to_string();
    run(
        "gpg",
        &[
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            &stdin,
            "--decrypt",
        ],
        Some(&format!("{phrase}\n{ciphertext}")),
    )
}

#[allow(dead_code)] // public API surface consumed by the HTTP layer / clients
/// True when the local keyring (plus any SKARBIEC_UNLOCK) opens this
/// ciphertext. Used to gate reads by possession.
pub fn can_decrypt(ciphertext: &str) -> bool {
    decrypt(ciphertext).is_ok()
}
