// Core of the skarbiec vault: cryptographic operations, the encrypted
// per-recipient vault document, and the typed item model. Sibling layers
// (access, runtime, net) build on these.

pub mod crypto;
pub mod items;
pub mod vault;

use std::path::PathBuf;

/// Location of the encrypted vault. An explicit `SKARBIEC_VAULT_FILE` wins;
/// otherwise use the user's Stado state directory, never the source tree.
pub fn vault_path() -> PathBuf {
    if let Ok(p) = std::env::var("SKARBIEC_VAULT_FILE") {
        return PathBuf::from(p);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".stado/skarbiec.vault.json")
}
