//! What the stored seed is, read without ever letting the seed itself out: the
//! shape a Base32 seed has to have, the states an item can be in, and the
//! six-digit code the seed produces when it is usable.

use anyhow::Result;
use serde_json::Value;

use crate::core::{vault::Vault, vault_path};

use crate::core::{schema, totp};

use super::SeedState;

pub(super) fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

/// The non-blank text stored in `totp_secret`, if the item's fields hold any.
pub(super) fn seed_of(payload: &Value) -> Option<&str> {
    payload
        .get("fields")
        .and_then(|fields| fields.get("totp_secret"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|seed| !seed.is_empty())
}

/// RFC 4648 Base32 uses eight-character blocks.
/// <https://www.rfc-editor.org/rfc/rfc4648#section-6>
pub(super) const BASE32_BLOCK_CHARS: usize = 8;
/// At most six `=` characters pad the final Base32 block.
/// <https://www.rfc-editor.org/rfc/rfc4648#section-6>
pub(super) const MAX_BASE32_PADDING_CHARS: usize = 6;
/// The Base32 alphabet. <https://www.rfc-editor.org/rfc/rfc4648#section-6>
const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// TOTP seeds are non-empty Base32 text, optionally followed by standard `=`
/// padding. How long a seed is, is the issuer's choice.
pub(crate) fn base32_seed_shape(seed: &str) -> bool {
    let data = seed.trim_end_matches('=');
    let padding = seed.len().saturating_sub(data.len());
    let unpadded = data.len() == seed.len();
    !data.is_empty()
        && padding <= MAX_BASE32_PADDING_CHARS
        && (unpadded || seed.len().is_multiple_of(BASE32_BLOCK_CHARS))
        && data.bytes().all(|byte| BASE32_ALPHABET.contains(&byte))
}

pub(super) struct SeedInspection {
    pub(super) state: SeedState,
    pub(super) code: Option<String>,
    /// Why a seed with the Base32 shape still produced no code.
    pub(super) reason: Option<String>,
}

/// Classify one canonical item payload against the same TOTP consumer used by
/// `totp`, computing the code for the Unix time `at` the caller read. The seed
/// never leaves this function; only the six-digit result can.
pub(super) fn inspect_seed(payload: &Value, at: u64) -> SeedInspection {
    let Some(seed) = seed_of(payload) else {
        let declares = payload
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| schema::kind_declares_field(kind, "totp_secret"));
        return SeedInspection {
            state: if declares {
                SeedState::DeclaredEmpty
            } else {
                SeedState::FieldAbsent
            },
            code: None,
            reason: None,
        };
    };
    if schema::is_placeholder(seed) {
        return SeedInspection {
            state: SeedState::Placeholder,
            code: None,
            reason: None,
        };
    }
    if !base32_seed_shape(seed) {
        return SeedInspection {
            state: SeedState::Invalid,
            code: None,
            reason: Some("the seed is not padded RFC 4648 Base32 text".to_string()),
        };
    }
    match totp::code(seed, at) {
        Ok(code) => SeedInspection {
            state: SeedState::Present,
            code: Some(code),
            reason: None,
        },
        Err(reason) => SeedInspection {
            state: SeedState::Invalid,
            code: None,
            reason: Some(reason),
        },
    }
}
