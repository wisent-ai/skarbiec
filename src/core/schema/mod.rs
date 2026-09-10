// The canonical item contract: which kinds exist, what a payload of each kind
// must contain, which tags may be written, and how an older item is read.

mod kinds;
mod legacy;
mod payload;
mod tags;

pub use legacy::migrate_legacy;
pub use payload::{
    allows_field, field, fields, kind_allows_field, kind_declares_field, payload,
    validate_payload,
};
pub use tags::ensure_registered_tags;

pub const ITEM_SCHEMA: &str = "skarbiec.item.v2";

/// The bound an exact name carries throughout this crate: non-empty, no longer
/// than this many bytes, and free of the separators a name must never smuggle
/// into a resource string, a route table row or a journal line.
pub const MAX_NAME_CHARS: usize = 128;

pub fn exact_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.contains('\0')
        && !value.contains('\n')
        && !value.contains('\r')
}
/// Whether one stored string is an operator placeholder rather than a
/// credential. Placeholders in imported fleet data are uppercase identifiers
/// joined with underscores (`WELES_ADMIN_GOOGLE_PASSWORD`); requiring the
/// underscore keeps ordinary all-uppercase secrets and Base32 TOTP seeds out
/// of this class.
pub fn is_placeholder(value: &str) -> bool {
    value.contains('_')
        && value.starts_with(|character: char| character.is_ascii_uppercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}


fn exact_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= "128".parse().unwrap_or(usize::MAX)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}


