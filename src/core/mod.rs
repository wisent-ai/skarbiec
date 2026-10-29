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
pub mod presence;
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

/// The uid this process acts as, read from the kernel. Every owner-only file
/// check compares the file's owner with it.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Stado's config file, the way Stado itself finds it: `$STADO_CONFIG`, then
/// `stado.config.json` in the working directory, `~/.config/stado/config.json`,
/// `~/.stado/config.json`. A candidate that cannot be examined is the cause,
/// not a missing file: read as missing, the search moved on to a later
/// candidate, or to none, and the vault routing came from the wrong place.
pub fn stado_config_file() -> Result<Option<PathBuf>, String> {
    if let Some(named) = std::env::var_os("STADO_CONFIG") {
        return Ok(Some(PathBuf::from(named)));
    }
    let home = home_dir();
    for candidate in [
        PathBuf::from("stado.config.json"),
        home.join(".config/stado/config.json"),
        home.join(".stado/config.json"),
    ] {
        match std::fs::metadata(&candidate) {
            Ok(metadata) if metadata.is_file() => return Ok(Some(candidate)),
            Ok(_not_file) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("Stado's config candidate {} cannot be examined: {error}", candidate.display()))
            }
        }
    }
    Ok(None)
}

/// Stado's config document, the way `stado_config_file` finds it; `None`
/// when there is no config file. A config that exists but cannot be read or
/// is not JSON is an error naming the file and cause: whether this machine
/// holds a vault cannot be told from it.
fn stado_document() -> Result<Option<serde_json::Value>, String> {
    let Some(file) = stado_config_file()? else {
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

/// Where a machine Stado makes a client of the vault owner reads the fleet
/// vault, and the declaration that says so.
pub struct OwnerRoute {
    /// The address of the owner's Skarbiec.
    pub route: String,
    /// What declares it: `secrets.skarbiec.url`, or the forward file.
    pub declared_by: String,
}

/// The route this machine reads the fleet vault through, when Stado says it
/// holds none itself: `secrets.skarbiec.vault_file` is not declared, and
/// either `secrets.skarbiec.url` is, or this host publishes the canonical
/// forward (`~/.stado/forwards/skarbiec.local`) Stado reads the vault through
/// when its config names no URL. Such a machine is a client of the vault
/// owner, and any vault file on it is a copy: the fleet keeps one vault, and
/// a write into a copy is a credential the owner never sees (a subscription
/// signed in on a laptop was stored in the laptop's leftover file while the
/// gateway kept reading the owner's). `None` when Stado names no route or
/// names a vault file here; the cause when the config or the forward cannot
/// be read.
pub fn remote_owner_route() -> Result<Option<OwnerRoute>, String> {
    if stado_declared_vault()?.is_some() {
        return Ok(None);
    }
    let configured = stado_document()?.and_then(|document| {
        document
            .pointer("/secrets/skarbiec/url")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(str::to_string)
    });
    if let Some(route) = configured {
        return Ok(Some(OwnerRoute { route, declared_by: "secrets.skarbiec.url".to_string() }));
    }
    let forward = crate::credential::published_canonical_forward().map_err(|error| format!("{error:#}"))?;
    Ok(forward.map(|(file, route)| OwnerRoute { route, declared_by: file.display().to_string() }))
}

/// The owner route that makes `path` a copy this machine does not open, when
/// nothing chose it: no request override and no `SKARBIEC_VAULT_FILE` named
/// it, Stado declares no vault file here, and Stado routes this machine to
/// the vault owner. `None` when `path` was chosen or no route stands; the
/// cause when the config or forward cannot be read.
pub fn unchosen_copy_route(path: &std::path::Path) -> Result<Option<OwnerRoute>, String> {
    let chosen = REQUEST_VAULT.with(|cell| cell.borrow().is_some())
        || std::env::var_os("SKARBIEC_VAULT_FILE").is_some();
    if chosen || path != default_vault_path() {
        return Ok(None);
    }
    remote_owner_route()
}

/// Why `path` may not be opened, when `unchosen_copy_route` names a route. A
/// bare `skarbiec` (or a product that runs it, as Brama does when it stores a
/// subscription) then lands on the leftover default file, which is a copy of
/// the fleet vault the owner never reads. A vault someone names explicitly is
/// theirs to open.
pub fn unchosen_copy_refusal(path: &std::path::Path) -> Option<String> {
    let OwnerRoute { route, declared_by } = match unchosen_copy_route(path) {
        Ok(Some(owner)) => owner,
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
         {declared_by} ({route}), so {} is a copy and is neither read nor written; \
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

/// A state file's text, or `None` only when it does not exist. Any failure
/// other than NotFound is the error, naming `what` and the path: `exists()`
/// answers false for a file that cannot be stat'ed too, and a state file read
/// as empty would be written over by the next save.
pub fn read_present(path: &std::path::Path, what: &str) -> anyhow::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(anyhow::Error::new(error).context(format!("read {what} {}", path.display())))
        }
    }
}

/// Whether a file exists, refusing a path that cannot be examined: only
/// NotFound is absence, and any other failure names `what` and the path.
/// `exists()` answers false for a file that cannot be stat'ed too, and an
/// unreadable vault read as no vault would make a rotation do nothing silently.
pub fn is_present(path: &std::path::Path, what: &str) -> anyhow::Result<bool> {
    Ok(file_type(path, what)?.is_some())
}

/// What kind of file a path names, following links, or None when nothing is
/// there; as with `is_present`, only NotFound is absence. `is_dir()` and
/// `is_file()` answer false for a path that cannot be stat'ed, which reads a
/// directory this process may not examine as one that is not a directory.
pub fn file_type(path: &std::path::Path, what: &str) -> anyhow::Result<Option<std::fs::FileType>> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata.file_type())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(anyhow::Error::new(error).context(format!("examine {what} {}", path.display())))
        }
    }
}

/// What a panic said: its message when the payload is text, and that it
/// carried none otherwise. Every thread join that ends in a panic reports
/// through this, so a stopped worker is named with its own words.
pub fn panic_reason(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = panic.downcast_ref::<String>() {
        return message.clone();
    }
    if let Some(message) = panic.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    "its payload is not text, so it carries no message".to_string()
}
