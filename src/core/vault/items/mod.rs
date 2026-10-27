// The items inside the vault: writing them, building their envelope, reading
// and listing them, the identity that survives a rename, and the saved
// versions a restore can bring back.

pub(in crate::core::vault) mod duplicates;
mod envelope;
mod identity;
mod lifecycle;
mod readers;
mod versions;
mod writes;

pub(in crate::core::vault) use envelope::{stored_history, stored_tags};
