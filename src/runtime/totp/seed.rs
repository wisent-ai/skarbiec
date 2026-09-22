//! What the stored seed is, read without ever letting the seed itself out: the
//! shape a Base32 seed has to have, the states an item can be in, and the
//! six-digit code the seed produces when it is usable.

use anyhow::Result;
use serde_json::Value;

use crate::core::{vault::Vault, vault_path};

use crate::core::{schema, totp};

use super::{SeedState, SEED_REPAIR_COMMAND};

pub(super) fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

/// The non-blank text stored in `totp_secret`, if there is any.
pub(super) fn seed_of(payload: &Value) -> Option<&str> {
    schema::field(payload, "totp_secret")
        .ok()
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|seed| !seed.is_empty())
}

/// Supported stored seeds contain 80 to 640 bits of Base32 data.
pub(super) const MIN_TOTP_SEED_BASE32_CHARS: usize = 16;
pub(super) const MAX_TOTP_SEED_BASE32_CHARS: usize = 128;
/// RFC 4648 Base32 uses eight-character blocks and at most six `=` characters
/// to pad the final block.
pub(super) const BASE32_BLOCK_CHARS: usize = 8;
pub(super) const MAX_BASE32_PADDING_CHARS: usize = 6;

/// TOTP seeds are Base32 text, optionally followed by standard `=` padding.
pub(super) fn base32_seed_shape(seed: &str) -> bool {
    let data = seed.trim_end_matches('=');
    let padding = seed.len().saturating_sub(data.len());
    (MIN_TOTP_SEED_BASE32_CHARS..=MAX_TOTP_SEED_BASE32_CHARS).contains(&data.len())
        && padding <= MAX_BASE32_PADDING_CHARS
        && (padding == 0 || seed.len().is_multiple_of(BASE32_BLOCK_CHARS))
        && data
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || matches!(byte, b'2'..=b'7'))
}

pub(super) struct SeedInspection {
    pub(super) state: SeedState,
    pub(super) code: Option<String>,
}

/// Classify one canonical item payload against the same TOTP consumer used by
/// `totp`. The seed never leaves this function; only the six-digit result can.
pub(super) fn inspect_seed(payload: &Value) -> SeedInspection {
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
        };
    };
    if schema::is_placeholder(seed) {
        return SeedInspection {
            state: SeedState::Placeholder,
            code: None,
        };
    }
    if !base32_seed_shape(seed) {
        return SeedInspection {
            state: SeedState::Invalid,
            code: None,
        };
    }
    match totp::code(seed) {
        Some(code) => SeedInspection {
            state: SeedState::Present,
            code: Some(code),
        },
        None => SeedInspection {
            state: SeedState::Invalid,
            code: None,
        },
    }
}

pub fn seed_state(payload: &Value) -> SeedState {
    inspect_seed(payload).state
}
