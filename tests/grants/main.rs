//! Grants driven through the real CLI against a real isolated vault. What a
//! grant may declare lives in `declaration`; what it lets a caller actually
//! do lives in `redemption`; the vault they both start from is `fixture`.

#[path = "../support/mod.rs"]
mod support;

mod declaration;
mod edits;
mod fixture;
mod redemption;
