// Durable browser integration owned by the Skarbiec binary. This replaces
// developer-only shell installers: one command rotates the browser's exact-field
// token and atomically installs native-messaging manifests for supported
// browsers.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::access::grant;
use crate::core::{schema, vault::Vault, vault_path};

const CONSUMER: &str = "skarbiec-browser-host";
const HOST_NAME: &str = "ai.wisent.skarbiec";
const CHROME_EXTENSION_ID: &str = include_str!("../deploy/chrome-extension-id");
/// The extension's own manifest declares the Firefox id it signs as; the
/// host's manifest names the same id, read from there rather than restated.
const EXTENSION_MANIFEST: &str = include_str!("../browser/manifest.json");

fn firefox_extension_id() -> Result<String> {
    let manifest: Value = serde_json::from_str(EXTENSION_MANIFEST)
        .context("browser/manifest.json, which this binary was built with, is not JSON")?;
    manifest
        .pointer("/browser_specific_settings/gecko/id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .context("browser/manifest.json declares no browser_specific_settings.gecko.id, the Firefox extension id the host must allow")
}

/// Owner read and write, the mode every private file the vault writes.
fn private_file_mode() -> Result<u32> {
    crate::core::vault::private_file_mode()
}

/// Owner read, write and search: the directory form of the same rule.
fn private_dir_mode() -> Result<u32> {
    Ok(u32::from(libc::S_IRWXU))
}

/// The origin Chrome names the extension by, and starts its host with.
fn chrome_origin() -> String {
    format!("chrome-extension://{CHROME_EXTENSION_ID}/")
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .context("HOME is required to install browser integration")
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(private_dir_mode()?)
        .create(path)
        .with_context(|| format!("create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(private_dir_mode()?))?;
    Ok(())
}

fn atomic_write(path: &Path, body: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("browser integration path has no parent")?;
    ensure_private_dir(parent)?;
    let temp = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(private_file_mode()?)
        .open(&temp)
        .with_context(|| format!("create {}", temp.display()))?;
    let result = (|| -> Result<()> {
        file.write_all(body)?;
        file.sync_all()?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(private_file_mode()?))?;
        fs::rename(&temp, path)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("flush browser integration directory {}", parent.display()))?;
        Ok(())
    })();
    if result.is_err() {
        crate::core::staging::remove_said(
            &temp,
            "a failed browser integration write left its temporary file",
        );
    }
    result
}

fn write_manifest(path: &Path, value: &Value) -> Result<()> {
    let mut encoded = serde_json::to_vec_pretty(value)?;
    encoded.push(b'\n');
    atomic_write(path, &encoded)
}

fn mint_browser_token() -> Result<String> {
    let vault = Vault::open(vault_path())?;
    let mut capabilities = Vec::new();
    for row in vault.list(false) {
        if row.get("kind").and_then(Value::as_str) != Some("login") {
            continue;
        }
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .context("canonical login row has no id")?;
        let payload = vault.get_item(id)?;
        capabilities.push(format!("read:{id}#context"));
        for field in ["username", "password", "totp_secret"] {
            if schema::field(&payload, field).is_ok() {
                capabilities.push(format!("read:{id}#{field}"));
            }
        }
    }
    if capabilities.is_empty() {
        bail!("no canonical login items are available for browser access");
    }
    // The extension may offer a new login, which waits sealed in the
    // donation inbox until the owner accepts it; it reads nothing.
    capabilities.push(format!("offer:{}", crate::net::api::offer::OFFERED));
    // Each install mints a fresh bearer, which retires the previous one; the
    // grant itself lives until `grant revoke`, because no lifetime was ever
    // stated for it and grant issue refuses to invent one.
    let flags = HashMap::from([
        ("capabilities".to_string(), capabilities.join(",")),
        ("until-revoked".to_string(), "true".to_string()),
    ]);
    let positionals = vec!["issue".to_string(), CONSUMER.to_string()];
    let minted = grant::dispatch("grant", &flags, &positionals)?
        .context("grant issue did not return a result")?;
    minted
        .get("token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .context("grant issue did not return a bearer token")
}

pub fn install_host(flags: &HashMap<String, String>) -> Result<Value> {
    if !cfg!(target_os = "macos") {
        bail!("browser install currently supports macOS only");
    }

    let binary = match flags.get("binary") {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe().context("resolve current Skarbiec binary")?,
    };
    let binary = fs::canonicalize(&binary)
        .with_context(|| format!("resolve browser host binary {}", binary.display()))?;
    if !crate::core::file_type(&binary, "the browser host binary")?.is_some_and(|kind| kind.is_file()) {
        bail!("browser host binary {} must be a regular file", binary.display());
    }

    let paths = HostPaths::of(&home_dir()?);
    let token = mint_browser_token()?;
    atomic_write(&paths.token, token.as_bytes())?;

    let chrome_manifest = json!({
        "name": HOST_NAME,
        "description": "Skarbiec vault bridge for the autofill extension",
        "path": binary,
        "type": "stdio",
        "allowed_origins": [chrome_origin()],
    });
    let firefox_id = firefox_extension_id()?;
    let firefox_manifest = json!({
        "name": HOST_NAME,
        "description": "Skarbiec vault bridge for the autofill extension",
        "path": binary,
        "type": "stdio",
        "allowed_extensions": [firefox_id],
    });

    write_manifest(&paths.chrome, &chrome_manifest)?;
    write_manifest(&paths.firefox, &firefox_manifest)?;

    Ok(json!({
        "ok": true,
        "consumer": CONSUMER,
        "capability_mode": "exact-login-fields",
        "binary": binary,
        "token_file": paths.token,
        "native_messaging_manifests": {
            "chrome": paths.chrome,
            "firefox": paths.firefox,
        },
        "chrome_extension_id": CHROME_EXTENSION_ID,
        "firefox_extension_id": firefox_id,
    }))
}

/// Where `browser install` puts the bearer and the two native-messaging
/// manifests; install, uninstall and status read the same three paths.
struct HostPaths {
    token: PathBuf,
    chrome: PathBuf,
    firefox: PathBuf,
}

/// The file name both browsers read the host's manifest under.
fn manifest_name() -> String {
    format!("{HOST_NAME}.json")
}

impl HostPaths {
    fn of(home: &Path) -> Self {
        let manifest = manifest_name();
        Self {
            token: home.join(".local/state/skarbiec/browser-host-token"),
            chrome: home
                .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
                .join(&manifest),
            firefox: home
                .join("Library/Application Support/Mozilla/NativeMessagingHosts")
                .join(&manifest),
        }
    }
}

/// Whether a path is there: absent is an answer, any other failure to look
/// is an error naming the path.
fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("examine {}", path.display())),
    }
}

mod command;
mod coverage;
pub use command::{command, launched};
pub use coverage::{cover_all, cover_login, maintain_pass as autofill_maintain_pass, reach as autofill_reach};

/// `browser status`: whether the autofill extension is connected here —
/// both manifests, the token file and the grant — what is missing when it is
/// half connected, and the logins the grant does not reach; running
/// `browser install` again repairs both.
pub fn host_status() -> Result<Value> {
    let paths = HostPaths::of(&home_dir()?);
    let chrome = present(&paths.chrome)?;
    let firefox = present(&paths.firefox)?;
    let token = present(&paths.token)?;
    let (grant, not_covered) = coverage::of(CONSUMER)?;
    Ok(json!({
        "ok": true,
        "consumer": CONSUMER,
        "connected": chrome && firefox && token && grant,
        "grant": grant,
        "logins_not_covered": not_covered,
        "token_file": {"path": paths.token, "present": token},
        "native_messaging_manifests": {
            "chrome": {"path": paths.chrome, "present": chrome},
            "firefox": {"path": paths.firefox, "present": firefox},
        },
    }))
}

/// `browser uninstall`: undo `browser install`. The two
/// native-messaging manifests and the token file go, and the browser host's
/// grant is revoked so the bearer that file held answers nothing even if a
/// copy survives. Each piece is reported as removed or already absent, so a
/// second run is harmless and says so.
pub fn uninstall_host() -> Result<Value> {
    let paths = HostPaths::of(&home_dir()?);
    let remove = |path: &Path| -> Result<bool> {
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
        }
    };
    let chrome_removed = remove(&paths.chrome)?;
    let firefox_removed = remove(&paths.firefox)?;
    let token_removed = remove(&paths.token)?;
    let positionals = vec!["revoke".to_string(), CONSUMER.to_string()];
    let revoked = grant::dispatch("grant", &HashMap::new(), &positionals)?
        .context("grant revoke did not return a result")?;
    Ok(json!({
        "ok": true,
        "consumer": CONSUMER,
        "grant_revoked": revoked.get("revoked"),
        "token_file": {"path": paths.token, "removed": token_removed},
        "native_messaging_manifests": {
            "chrome": {"path": paths.chrome, "removed": chrome_removed},
            "firefox": {"path": paths.firefox, "removed": firefox_removed},
        },
    }))
}
