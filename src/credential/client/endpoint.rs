// Where the canonical Skarbiec is: one owner-controlled Stado forward file,
// never an environment URL, and the refusal that names what is missing.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::net::TcpStream;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::super::common::effective_uid;
use super::{
    CANONICAL_FORWARD, ENDPOINT_TLS_UNSUPPORTED, ENDPOINT_UNRESOLVED, FORWARDS_DIR_ENV, LOOPBACK,
};

pub(in crate::credential) fn forwards_dir() -> Result<PathBuf> {
    if let Ok(configured) = std::env::var(FORWARDS_DIR_ENV) {
        if !configured.trim().is_empty() {
            return Ok(PathBuf::from(configured.trim()));
        }
    }
    let home = std::env::var("HOME")
        .ok()
        .filter(|home| !home.trim().is_empty())
        .with_context(|| {
            format!("{ENDPOINT_UNRESOLVED}: neither {FORWARDS_DIR_ENV} nor HOME is set")
        })?;
    Ok(Path::new(home.trim()).join(".stado").join("forwards"))
}

/// The remedy every `SKARBIEC_ENDPOINT_UNRESOLVED` carries.
///
/// A fresh installation has no forward file, so this error is the first thing
/// a new operator sees from `credential`, and until now it named a path with
/// no way to produce one - the product enforced a contract it gave nobody the
/// means to satisfy.
const ENDPOINT_REMEDY: &str = "declare it with `skarbiec credential declare-endpoint <url>`";

// The canonical Skarbiec is the only remote hop, and its address comes from
// one owner-controlled Stado forward file.
pub(in crate::credential) fn canonical_endpoint() -> Result<String> {
    let path = forwards_dir()?.join(CANONICAL_FORWARD);
    let metadata = fs::symlink_metadata(&path).with_context(|| {
        format!(
            "{ENDPOINT_UNRESOLVED}: no canonical forward at {}; {ENDPOINT_REMEDY}",
            path.display()
        )
    })?;
    let group_world_write = u32::from_str_radix("022", "8".parse()?)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid()?
        || metadata.permissions().mode() & group_world_write != u32::MIN
    {
        bail!(
            "{ENDPOINT_UNRESOLVED}: {} must be an owner-owned regular file without group or world write; {ENDPOINT_REMEDY}",
            path.display()
        );
    }
    let max: usize = "256".parse()?;
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("{ENDPOINT_UNRESOLVED}: read {}", path.display()))?;
    let endpoint = raw.trim().to_string();
    if endpoint.is_empty() || endpoint.len() > max || endpoint.chars().any(char::is_control) {
        bail!(
            "{ENDPOINT_UNRESOLVED}: {} must hold exactly one bounded URL; {ENDPOINT_REMEDY}",
            path.display()
        );
    }
    Ok(endpoint)
}

/// The canonical endpoint as it stands, without writing anything.
///
/// `doctor` needs the same three facts `declare-endpoint` reports - which
/// file, which address, does it answer - and must not create a file while
/// diagnosing the absence of one.
pub(in crate) fn canonical_endpoint_report() -> Result<Value> {
    let path = forwards_dir()?.join(CANONICAL_FORWARD);
    let endpoint = canonical_endpoint()?;
    let authority = endpoint_authority(&endpoint)?;
    Ok(json!({
        "forward": path.display().to_string(),
        "endpoint": endpoint,
        "authority": authority,
        "answering": TcpStream::connect(&authority).is_ok(),
    }))
}

/// Write the canonical forward file this module reads.
///
/// Nothing in this product wrote it. The reader above enforces a precise
/// contract - owner-owned, no group or world write, exactly one bounded URL -
/// and every fresh installation has no such file at all, so the first
/// `credential` call on a new machine failed with a path and no way to
/// produce it. Measured on this host: the file existed from an earlier
/// session naming port 8785, which no Skarbiec serves; the default is 8787.
///
/// The declaration is verified through `canonical_endpoint` before returning,
/// so a file this command wrote can never be one the reader rejects.
pub(in crate::credential) fn declare_canonical_endpoint(endpoint: &str) -> Result<Value> {
    let endpoint = endpoint.trim();
    let directory = forwards_dir()?;
    let owner_only_directory = u32::from_str_radix("700", "8".parse()?)?;
    let owner_only_file = u32::from_str_radix("600", "8".parse()?)?;
    fs::create_dir_all(&directory)
        .with_context(|| format!("create forwards directory {}", directory.display()))?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(owner_only_directory))
        .with_context(|| format!("protect forwards directory {}", directory.display()))?;
    let path = directory.join(CANONICAL_FORWARD);
    let staging = path.with_extension("local.staging");
    fs::write(&staging, format!("{endpoint}\n"))
        .with_context(|| format!("write {}", staging.display()))?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(owner_only_file))
        .with_context(|| format!("protect {}", staging.display()))?;
    fs::rename(&staging, &path).with_context(|| format!("publish {}", path.display()))?;
    let declared = canonical_endpoint()?;
    let authority = endpoint_authority(&declared)?;
    // Whether anything answers is a separate question from whether the
    // declaration is well formed, and the report says both rather than
    // conflating them the way a bare connection error does.
    let answering = TcpStream::connect(&authority).is_ok();
    Ok(json!({
        "forward": path.display().to_string(),
        "endpoint": declared,
        "authority": authority,
        "answering": answering,
    }))
}

// https is a valid canonical endpoint but needs a TLS client this binary does
// not carry, so only a loopback forward is reachable in process.
pub(in crate::credential) fn endpoint_authority(endpoint: &str) -> Result<String> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .with_context(|| format!("{ENDPOINT_UNRESOLVED}: {endpoint} is not an absolute URL"))?;
    let authority = rest.trim_end_matches('/');
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('@')
        || authority.chars().any(char::is_whitespace)
    {
        bail!("{ENDPOINT_UNRESOLVED}: {endpoint} must name one host and port and no path");
    }
    let (host, port) = authority
        .rsplit_once(':')
        .with_context(|| format!("{ENDPOINT_UNRESOLVED}: {endpoint} must name an exact port"))?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("{ENDPOINT_UNRESOLVED}: {endpoint} must name an exact numeric port");
    }
    let loopback = matches!(host, LOOPBACK | "localhost" | "[::1]");
    match scheme {
        "https" => bail!(
            "{ENDPOINT_TLS_UNSUPPORTED}: {endpoint} needs a TLS client; publish the canonical Skarbiec through a loopback Stado forward instead"
        ),
        "http" if loopback => Ok(authority.to_string()),
        _ => bail!(
            "{ENDPOINT_UNRESOLVED}: {endpoint} must be https or http on the loopback interface"
        ),
    }
}

pub(in crate::credential) fn stale_service_directory(value: &Value) -> bool {
    let text = format!(
        "{} {}",
        value
            .get("error_code")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or_default()
    )
    .to_lowercase();
    text.contains("service_directory_stale")
        || (text.contains("service directory") && text.contains("stale"))
}
