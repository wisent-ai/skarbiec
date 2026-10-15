// Verifying a workload's Ed25519 signature with the local OpenSSL, the one
// place proof checks ask.
//
// The answer has three outcomes, not two. OpenSSL saying the signature does
// not verify is a denial; OpenSSL that cannot run, cannot read the key, or
// cannot do Ed25519 at all (Apple's LibreSSL `pkeyutl`) is an error with its
// own words. Read as a bad signature, a broken verifier denied every correctly
// signed redemption and told the operator only "denied".

use anyhow::{bail, Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// What `openssl pkeyutl -verify` prints when the signature does not match.
/// It exits non-zero for this and for every error alike, so the sentence is
/// what tells a denial from a verifier that could not answer.
const VERIFICATION_FAILURE: &str = "Signature Verification Failure";

/// The `openssl` proofs are verified with: SKARBIEC_OPENSSL when it names one,
/// otherwise Homebrew's linked OpenSSL when it is installed, otherwise
/// `openssl` on PATH.
fn openssl_bin() -> PathBuf {
    if let Some(configured) = crate::core::env::path("SKARBIEC_OPENSSL") {
        return configured;
    }
    for candidate in ["/opt/homebrew/bin/openssl", "/usr/local/bin/openssl"] {
        if Path::new(candidate).is_file() {
            return candidate.into();
        }
    }
    "openssl".into()
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(crate::core::vault::private_file_mode()?)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("flush {}", path.display()))
}

/// Whether `signature` is `public_key`'s Ed25519 signature over `payload`.
///
/// `Ok(false)` is OpenSSL's own verdict that it is not. Every other way the
/// check can end -- the scratch files, the child, an OpenSSL that cannot read
/// the key or does not support Ed25519 -- is the error, naming `what` and
/// OpenSSL's words. The three owner-only scratch files live in `scratch` and
/// are removed whatever the outcome.
pub fn verify(
    public_key: &str,
    payload: &[u8],
    signature: &[u8],
    scratch: &Path,
    what: &str,
) -> Result<bool> {
    std::fs::create_dir_all(scratch)
        .with_context(|| format!("create {what} directory {}", scratch.display()))?;
    let stem = super::sha256_hex(&super::random_token()?)?;
    let key_path = scratch.join(format!(".skarbiec-proof-key-{stem}"));
    let signature_path = scratch.join(format!(".skarbiec-proof-signature-{stem}"));
    let payload_path = scratch.join(format!(".skarbiec-proof-payload-{stem}"));
    let openssl = openssl_bin();
    let result = (|| -> Result<bool> {
        write_owner_only(&key_path, public_key.as_bytes())?;
        write_owner_only(&signature_path, signature)?;
        write_owner_only(&payload_path, payload)?;
        let output = stado_wait::output(
            Command::new(&openssl)
                .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
                .arg(&key_path)
                .args(["-rawin", "-sigfile"])
                .arg(&signature_path)
                .arg("-in")
                .arg(&payload_path),
        )
        .with_context(|| format!("run {} to verify {what}", openssl.display()))?;
        if output.status.success() {
            return Ok(true);
        }
        if String::from_utf8_lossy(&output.stdout).contains(VERIFICATION_FAILURE) {
            return Ok(false);
        }
        bail!(
            "{} could not verify {what} ({}): {}; SKARBIEC_OPENSSL names an Ed25519-capable OpenSSL",
            openssl.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )
    })();
    for path in [&key_path, &signature_path, &payload_path] {
        crate::core::staging::remove_said(path, &format!("a {what} verification file"));
    }
    result
}
