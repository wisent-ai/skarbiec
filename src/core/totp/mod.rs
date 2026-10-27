//! The documented SHA1, six-digit, thirty-second authenticator, without a host tool.
use base32::Alphabet;
use totp_rs::{Algorithm, TOTP};

/// Digits of the code authenticator apps show.
/// <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
pub(crate) const DIGITS: usize = 6;
/// Seconds one code stays current: RFC 6238's default time step X.
/// <https://www.rfc-editor.org/rfc/rfc6238#section-4.1>
pub(crate) const PERIOD_SECONDS: u64 = 30;
/// Time steps of clock drift accepted either side: none, since this computes
/// the current code rather than checking one.
/// <https://www.rfc-editor.org/rfc/rfc6238#section-5.2>
const SKEW_STEPS: u8 = 0;

/// Decode the stored Base32 seed and compute its RFC 6238 code for the Unix
/// time `at`, or say why the seed makes none: it is not Base32, or it decodes
/// to no bytes. The caller reads the clock ([`crate::core::clock::epoch_seconds`])
/// and refuses with its own cause, so a clock that cannot be read is never
/// reported as a bad seed.
/// The existing eighty-bit seeds remain valid; `TOTP::new` would impose a new
/// minimum key length, so only its constructor validation is bypassed here.
pub fn code(seed: &str, at: u64) -> Result<String, String> {
    let secret = base32::decode(
        Alphabet::Rfc4648 {
            padding: seed.ends_with('='),
        },
        seed,
    )
    .ok_or_else(|| "the seed is not RFC 4648 Base32".to_string())?;
    if secret.is_empty() {
        return Err("the seed decodes to no bytes".to_string());
    }
    Ok(TOTP::new_unchecked(Algorithm::SHA1, DIGITS, SKEW_STEPS, PERIOD_SECONDS, secret).generate(at))
}
