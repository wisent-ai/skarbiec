// Core of the skarbiec vault: cryptographic operations, the encrypted
// per-recipient vault document, and the typed item model. Sibling layers
// (access, runtime, net) build on these.

pub mod clock;
pub mod crypto;
pub mod importer;
pub mod inbox;
pub mod items;
pub mod migrate;
pub mod schema;
pub mod totp;
pub mod values;
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
/// then an explicit `SKARBIEC_VAULT_FILE`, then the vault Stado declares for
/// this machine; only a machine nothing declares for falls back to the
/// product-owned user data directory, never the source tree.
///
/// The fleet's architecture keeps one vault per machine and declares its
/// location in Stado (`secrets.skarbiec.vault_file`); every unit Stado
/// renders receives it as `SKARBIEC_VAULT_FILE`. A bare `skarbiec` in an
/// operator's or an agent's shell received nothing and used the default, so
/// on 2026-09-16 one laptop held two vaults under one owner - 663 items at
/// the declared path, 661 at the default - and which one a command read
/// depended on who had launched it. Reading the declaration here ends that:
/// the same file answers a service and a shell.
pub fn vault_path() -> PathBuf {
    if let Some(path) = REQUEST_VAULT.with(|cell| cell.borrow().clone()) {
        return path;
    }
    if let Ok(p) = std::env::var("SKARBIEC_VAULT_FILE") {
        return PathBuf::from(p);
    }
    if let Some(declared) = stado_declared_vault() {
        return declared;
    }
    default_vault_path()
}

/// The path the product falls back to when neither an override nor a Stado
/// declaration names a vault.
pub fn default_vault_path() -> PathBuf {
    home_dir().join(".local/share/skarbiec/skarbiec.vault.json")
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Stado's config file, the way Stado itself finds it: `$STADO_CONFIG`, then
/// `stado.config.json` in the working directory, `~/.config/stado/config.json`,
/// `~/.stado/config.json`.
pub fn stado_config_file() -> Option<PathBuf> {
    if let Some(named) = std::env::var_os("STADO_CONFIG") {
        return Some(PathBuf::from(named));
    }
    let home = home_dir();
    [
        PathBuf::from("stado.config.json"),
        home.join(".config/stado/config.json"),
        home.join(".stado/config.json"),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
}

/// The vault Stado declares for this machine as `secrets.skarbiec.vault_file`,
/// tilde-expanded; `None` when no config file, no declaration, or an
/// unreadable file - an unreadable declaration is not a different vault.
pub fn stado_declared_vault() -> Option<PathBuf> {
    let file = stado_config_file()?;
    let text = std::fs::read_to_string(&file).ok()?;
    let document: serde_json::Value = serde_json::from_str(&text).ok()?;
    let declared = document
        .pointer("/secrets/skarbiec/vault_file")?
        .as_str()?
        .trim();
    if declared.is_empty() {
        return None;
    }
    Some(match declared.strip_prefix("~/") {
        Some(rest) => home_dir().join(rest),
        None => PathBuf::from(declared),
    })
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
