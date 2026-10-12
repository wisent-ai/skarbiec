//! What an inbound donation may do to its item, given the item's provenance.

use serde_json::Value;

use super::{managed_by_weles, written_by};
use crate::core::vault::Vault;

/// The admission rule of one donation, decided from the item's own state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The item belongs to a credential lifecycle, which owns its writes.
    CredentialLifecycle,
    /// No such item yet: the donation creates it.
    Append,
    /// Weles manages the item.
    Managed,
    /// The donor wrote the current revision and may replace it.
    Overwrite,
    /// Somebody else wrote the current revision.
    NotOwner,
    /// The item predates provenance and keeps the original rule.
    Exists,
}

impl Admission {
    /// Whether the donation may be written: a new item, or one its donor wrote.
    pub fn admits(self) -> bool {
        matches!(self, Self::Append | Self::Overwrite)
    }

    /// The rule's name on the wire, in audit entries and in refusals.
    pub fn name(self) -> &'static str {
        match self {
            Self::CredentialLifecycle => "credential-lifecycle",
            Self::Append => "append",
            Self::Managed => "managed",
            Self::Overwrite => "overwrite",
            Self::NotOwner => "not-owner",
            Self::Exists => "exists",
        }
    }
}

/// What an inbound donation for `item_id` may do, given current provenance.
/// `from` is the writer identity claimed by the donor (v1: the consumer).
pub fn admission(vault: &Vault, item_id: &str, from: &str) -> Admission {
    if crate::credential::lifecycle_owned_item(vault, item_id) {
        return Admission::CredentialLifecycle;
    }
    let exists = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .is_some_and(|items| items.contains_key(item_id));
    if !exists {
        return Admission::Append;
    }
    if managed_by_weles(vault, item_id) {
        return Admission::Managed;
    }
    match written_by(vault, item_id) {
        Some(owner) if owner == from => Admission::Overwrite,
        Some(_) => Admission::NotOwner,
        // Items written before provenance existed keep the original v1 rule.
        None => Admission::Exists,
    }
}
