//! The documented SHA1, six-digit, thirty-second authenticator, without a host tool.
use base32::Alphabet;
use totp_rs::{Algorithm, TOTP};

const DIGITS: usize = 6;
const PERIOD_SECONDS: u64 = 30;

/// Decode the stored Base32 seed and compute its current RFC 6238 code.
/// The existing eighty-bit seeds remain valid; `TOTP::new` would impose a new
/// minimum key length, so only its constructor validation is bypassed here.
pub fn code(seed: &str) -> Option<String> {
    let secret = base32::decode(
        Alphabet::Rfc4648 {
            padding: seed.ends_with('='),
        },
        seed,
    )?;
    if secret.is_empty() {
        return None;
    }
    TOTP::new_unchecked(Algorithm::SHA1, DIGITS, 0, PERIOD_SECONDS, secret)
        .generate_current()
        .ok()
}
