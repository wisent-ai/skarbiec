// Core of the skarbiec vault: cryptographic operations, the encrypted
// per-recipient vault document, and the typed item model. Sibling layers
// (access, runtime, net) build on these.

pub mod crypto;
pub mod inbox;
pub mod items;
pub mod migrate;
pub mod schema;
pub mod vault;

use std::cell::RefCell;
use std::path::PathBuf;

thread_local! {
    /// The vault one in-flight request operates on. The loopback listener
    /// handles each connection on its own thread from parse to response, so
    /// an operator console naming a vault per request can no more race another
    /// request than two backend processes can share one thread.
    static REQUEST_VAULT: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Location of the encrypted vault. A request-scoped override wins first,
/// then an explicit `SKARBIEC_VAULT_FILE`; otherwise use the product-owned
/// user data directory, never the source tree.
pub fn vault_path() -> PathBuf {
    if let Some(path) = REQUEST_VAULT.with(|cell| cell.borrow().clone()) {
        return path;
    }
    if let Ok(p) = std::env::var("SKARBIEC_VAULT_FILE") {
        return PathBuf::from(p);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local/share/skarbiec/skarbiec.vault.json")
}

/// Run one request's work against the vault it named, restoring the previous
/// selection afterwards. `None` leaves the process default in place.
pub fn with_vault_override<T>(path: Option<PathBuf>, work: impl FnOnce() -> T) -> T {
    REQUEST_VAULT.with(|cell| {
        let previous = cell.replace(path);
        let result = work();
        cell.replace(previous);
        result
    })
}
