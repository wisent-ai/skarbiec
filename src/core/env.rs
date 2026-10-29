//! Skarbiec's environment overrides, read one way everywhere.
//!
//! Only an unset (or blank) variable is absence. `std::env::var` answers
//! `NotUnicode` for a value that is set but not UTF-8, which must not pass as
//! unset: a path is therefore read as the OS hands it over, and a text value
//! that is set but not UTF-8 is an error naming the variable.

use anyhow::{bail, Result};
use std::path::PathBuf;

/// The path `name` names, as the OS gives it; `None` when it is unset or
/// blank.
pub fn path(name: &str) -> Option<PathBuf> {
    let value = std::env::var_os(name)?;
    if value.as_encoded_bytes().iter().all(u8::is_ascii_whitespace) {
        return None;
    }
    Some(PathBuf::from(value))
}

/// The text `name` holds; `None` when it is unset or blank, and an error
/// naming the variable when it is set but not UTF-8.
#[allow(
    clippy::disallowed_methods,
    reason = "the one reader every other override goes through"
)]
pub fn text(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("{name} is set but is not UTF-8 text; set it to the value, or unset it")
        }
    }
}
