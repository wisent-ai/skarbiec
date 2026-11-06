//! The documented SHA1, six-digit, thirty-second authenticator, without a host tool.
use base32::Alphabet;
use skarbiec_crypto::hmac::hmac_into;
use skarbiec_crypto::sha::Sha1;

/// Digits of the code authenticator apps show.
/// <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
pub(crate) const DIGITS: usize = 6;
/// Seconds one code stays current: RFC 6238's default time step X.
/// <https://www.rfc-editor.org/rfc/rfc6238#section-4.1>
pub(crate) const PERIOD_SECONDS: u64 = 30;
/// Ten to the power of [`DIGITS`]: the modulus RFC 4226 section 5.3 reduces by.
const MODULUS: u32 = 1_000_000;

/// Decode the stored Base32 seed and compute its RFC 6238 code for the Unix
/// time `at`, or say why the seed makes none: it is not Base32, or it decodes
/// to no bytes. The caller reads the clock ([`crate::core::clock::epoch_seconds`])
/// and refuses with its own cause, so a clock that cannot be read is never
/// reported as a bad seed. Any seed length is accepted, as RFC 4226 allows,
/// so the existing eighty-bit seeds remain valid.
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
    Ok(hotp(&secret, at / PERIOD_SECONDS))
}

/// RFC 4226 section 5.3: HMAC-SHA1 of the big-endian counter, dynamically
/// truncated to 31 bits, reduced to [`DIGITS`] digits.
fn hotp(secret: &[u8], counter: u64) -> String {
    let mut mac = [0u8; 20];
    hmac_into::<Sha1>(secret, &counter.to_be_bytes(), &mut mac);
    let offset = usize::from(mac[19] & 0x0f);
    let word = u32::from_be_bytes([
        mac[offset],
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]) & 0x7fff_ffff;
    format!("{:0width$}", word % MODULUS, width = DIGITS)
}
