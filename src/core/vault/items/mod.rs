// The items inside the vault: writing them, building their envelope, reading
// and listing them, and the identity that survives a rename.

pub(in crate::core::vault) mod duplicates;
mod envelope;
mod identity;
mod lifecycle;
mod writes;
