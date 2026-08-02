// Durable browser integration owned by the Skarbiec binary. This replaces
// developer-only shell installers: one command rotates the scoped browser
// token and atomically installs native-messaging manifests for supported
// browsers.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::access::tokens;

const CONSUMER: &str = "skarbiec-browser-host";
const HOST_NAME: &str = "ai.wisent.skarbiec";
const CHROME_EXTENSION_ID: &str = include_str!("../deploy/chrome-extension-id");
const FIREFOX_EXTENSION_ID: &str = "skarbiec-autofill@wisent.ai";

fn private_file_mode() -> Result<u32> {
    u32::from_str_radix("600", "8".parse()?).context("private file mode")
}

fn private_dir_mode() -> Result<u32> {
    u32::from_str_radix("700", "8".parse()?).context("private directory mode")
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .context("HOME is required to install browser integration")
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(private_dir_mode()?)
            .create(path)
            .with_context(|| format!("create {}", path.display()))?;
    }
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
        let _ = File::open(parent).and_then(|directory| directory.sync_all());
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn write_manifest(path: &Path, value: &Value) -> Result<()> {
    let mut encoded = serde_json::to_vec_pretty(value)?;
    encoded.push(b'\n');
    atomic_write(path, &encoded)
}

fn mint_browser_token() -> Result<String> {
    let flags = HashMap::from([("scopes".to_string(), "read:login-*".to_string())]);
    let positionals = vec![CONSUMER.to_string()];
    let minted = tokens::dispatch("token-mint", &flags, &positionals)?
        .context("token-mint did not return a result")?;
    minted
        .get("token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .context("token-mint did not return a bearer token")
}

pub fn install_host(flags: &HashMap<String, String>) -> Result<Value> {
    if !cfg!(target_os = "macos") {
        bail!("browser-host-install currently supports macOS only");
    }

    let binary = match flags.get("binary") {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe().context("resolve current Skarbiec binary")?,
    };
    let binary = fs::canonicalize(&binary)
        .with_context(|| format!("resolve browser host binary {}", binary.display()))?;
    if !binary.is_file() {
        bail!("browser host binary must be a regular file");
    }

    let home = home_dir()?;
    let token_path = home.join(".local/state/skarbiec/browser-host-token");
    let token = mint_browser_token()?;
    atomic_write(&token_path, token.as_bytes())?;

    let chrome_manifest = json!({
        "name": HOST_NAME,
        "description": "Skarbiec vault bridge for the autofill extension",
        "path": binary,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{CHROME_EXTENSION_ID}/")],
    });
    let firefox_manifest = json!({
        "name": HOST_NAME,
        "description": "Skarbiec vault bridge for the autofill extension",
        "path": binary,
        "type": "stdio",
        "allowed_extensions": [FIREFOX_EXTENSION_ID],
    });

    let chrome_path = home
        .join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    let firefox_path = home
        .join("Library/Application Support/Mozilla/NativeMessagingHosts")
        .join(format!("{HOST_NAME}.json"));
    write_manifest(&chrome_path, &chrome_manifest)?;
    write_manifest(&firefox_path, &firefox_manifest)?;

    Ok(json!({
        "ok": true,
        "consumer": CONSUMER,
        "scope": "read:login-*",
        "binary": binary,
        "token_file": token_path,
        "native_messaging_manifests": {
            "chrome": chrome_path,
            "firefox": firefox_path,
        },
        "chrome_extension_id": CHROME_EXTENSION_ID,
        "firefox_extension_id": FIREFOX_EXTENSION_ID,
    }))
}
