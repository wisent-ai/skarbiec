// Core of the skarbiec vault: cryptographic operations, the encrypted
// per-recipient vault document, and the typed item model. Sibling layers
// (access, runtime, net) build on these.

pub mod chrome_cards;
pub mod crypto;
pub mod items;
pub mod vault;

use std::path::PathBuf;

/// Location of the on-disk encrypted vault: SKARBIEC_VAULT_FILE override, else
/// a repo-relative default. Shared by every layer so they open one store.
pub fn vault_path() -> PathBuf {
    if let Ok(p) = std::env::var("SKARBIEC_VAULT_FILE") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("skarbiec.vault.json")
}
