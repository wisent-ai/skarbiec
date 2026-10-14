// Core of the skarbiec vault: cryptographic operations, the encrypted
// per-recipient vault document, and the typed item model. Sibling layers
// (access, runtime, net) build on these.

pub mod clock;
pub mod crypto;
pub mod env;
pub mod importer;
pub mod inbox;
pub mod items;
pub mod migrate;
pub mod schema;
pub mod staging;
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
/// one laptop could hold two vaults under one owner - nearly identical item
/// counts at the declared path and at the default - and which one a command
/// read depended on who had launched it. Reading the declaration here ends that:
/// the same file answers a service and a shell.
pub fn vault_path() -> PathBuf {
    if let Some(path) = REQUEST_VAULT.with(|cell| cell.borrow().clone()) {
        return path;
    }
    // Read as the operating system holds it, the same way owner routing
    // (`net::owner::selected`) detects the override, so a path that is not
    // UTF-8 selects that vault instead of disabling routing and then being
    // ignored here.
    if let Some(path) = std::env::var_os("SKARBIEC_VAULT_FILE") {
        return PathBuf::from(path);
    }
    if let Ok(Some(declared)) = stado_declared_vault() {
        return declared;
    }
    default_vault_path()
}

/// The path the product falls back to when neither an override nor a Stado
/// declaration names a vault.
pub fn default_vault_path() -> PathBuf {
    home_dir().join(".local/share/skarbiec/skarbiec.vault.json")
}

/// The user's home: HOME, else the home the user database records. With
/// neither, Skarbiec stops with the cause; reading `.` as home opened, or
/// created, a second empty vault under whatever directory it started from.
pub(crate) fn home_dir() -> PathBuf {
    std::env::home_dir().expect(
        "neither HOME nor the user database names a home directory, so the default vault cannot be found",
    )
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

/// Stado's config document, the way `stado_config_file` finds it; `None`
/// when there is no config file. A config that exists but cannot be read or
/// is not JSON is an error naming the file and cause: whether this machine
/// holds a vault cannot be told from it.
fn stado_document() -> Result<Option<serde_json::Value>, String> {
    let Some(file) = stado_config_file() else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(&file)
        .map_err(|error| format!("Stado's config {} cannot be read: {error}", file.display()))?;
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|error| format!("Stado's config {} is not JSON: {error}", file.display()))
}

/// The vault Stado declares for this machine as `secrets.skarbiec.vault_file`,
/// tilde-expanded; `None` when no config file or no declaration, and the
/// cause when the config cannot be read.
pub fn stado_declared_vault() -> Result<Option<PathBuf>, String> {
    let Some(document) = stado_document()? else {
        return Ok(None);
    };
    let declared = match document
        .pointer("/secrets/skarbiec/vault_file")
        .and_then(|value| value.as_str())
    {
        Some(declared) => declared.trim(),
        None => return Ok(None),
    };
    if declared.is_empty() {
        return Ok(None);
    }
    Ok(Some(match declared.strip_prefix("~/") {
        Some(rest) => home_dir().join(rest),
        None => PathBuf::from(declared),
    }))
}

/// The route this machine reads the fleet vault through, when Stado says it
/// holds none itself: `secrets.skarbiec.url` is declared and
/// `secrets.skarbiec.vault_file` is not. Such a machine is a client of the
/// vault owner, and any vault file on it is a copy: the fleet keeps one
/// vault, and a write into a copy is a credential the owner never sees (a
/// subscription signed in on a laptop was stored in the laptop's leftover
/// file while the gateway kept reading the owner's). `None` when Stado names
/// no route or names a vault file here; the cause when the config cannot be
/// read.
pub fn remote_owner_route() -> Result<Option<String>, String> {
    let Some(document) = stado_document()? else {
        return Ok(None);
    };
    if stado_declared_vault()?.is_some() {
        return Ok(None);
    }
    Ok(document
        .pointer("/secrets/skarbiec/url")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_string))
}

/// Why `path` may not be opened, when nothing chose it: no request override
/// and no `SKARBIEC_VAULT_FILE` named it, Stado declares no vault file here,
/// and Stado routes this machine to the vault owner. A bare `skarbiec` (or a
/// product that runs it, as Brama does when it stores a subscription) then
/// lands on the leftover default file, which is a copy of the fleet vault the
/// owner never reads. A vault someone names explicitly is theirs to open.
pub fn unchosen_copy_refusal(path: &std::path::Path) -> Option<String> {
    let chosen = REQUEST_VAULT.with(|cell| cell.borrow().is_some())
        || std::env::var_os("SKARBIEC_VAULT_FILE").is_some();
    if chosen || path != default_vault_path() {
        return None;
    }
    let route = match remote_owner_route() {
        Ok(Some(route)) => route,
        Ok(None) => return None,
        Err(cause) => {
            return Some(format!(
                "{} is the default vault and {cause}, so whether this machine holds a vault of its own \
                 cannot be told; repair the config, or name a vault with SKARBIEC_VAULT_FILE",
                path.display()
            ))
        }
    };
    Some(format!(
        "this machine holds no Skarbiec vault: Stado reads the fleet vault through \
         secrets.skarbiec.url ({route}), so {} is a copy and is neither read nor written; \
         work on the vault owner (stado credentials vault names it), or name a vault of \
         your own with SKARBIEC_VAULT_FILE",
        path.display()
    ))
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

/// A state file's text, or `None` only when it does not exist. Testing
/// `exists()` first answers false for a file that cannot be stat'ed too, so
/// an unreadable inbox, capability state or route table read as empty and the
/// next save wrote that empty document over it; any failure other than
/// NotFound is the error, naming `what` and the path.
pub fn read_present(path: &std::path::Path, what: &str) -> anyhow::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(anyhow::Error::new(error).context(format!("read {what} {}", path.display())))
        }
    }
}
