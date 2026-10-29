// Where the canonical Skarbiec is: one owner-controlled Stado forward file,
// never an environment URL, and the refusal that names what is missing.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::net::TcpStream;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

use stado_wait as wait;

use super::{
    CANONICAL_FORWARD, ENDPOINT_TLS_UNSUPPORTED, ENDPOINT_UNRESOLVED, FORWARDS_DIR_ENV, LOOPBACK,
};
use crate::core::effective_uid;

pub(in crate::credential) fn forwards_dir() -> Result<PathBuf> {
    if let Some(configured) = crate::core::env::path(FORWARDS_DIR_ENV) {
        return Ok(configured);
    }
    let home = std::env::home_dir().with_context(|| {
        format!("{ENDPOINT_UNRESOLVED}: neither {FORWARDS_DIR_ENV} nor HOME nor the user database names a directory")
    })?;
    Ok(home.join(".stado").join("forwards"))
}

/// The remedy every `SKARBIEC_ENDPOINT_UNRESOLVED` carries.
///
/// A fresh installation has no forward file, so this error is the first thing
/// a new operator sees from `credential`, and until now it named a path with
/// no way to produce one - the product enforced a contract it gave nobody the
/// means to satisfy.
const ENDPOINT_REMEDY: &str = "declare it with `skarbiec credential endpoint declare <url>`";

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
    let group_world_write = crate::core::mode::GROUP_AND_OTHER_WRITE;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid()
        || (metadata.permissions().mode() & group_world_write) != 0
    {
        bail!(
            "{ENDPOINT_UNRESOLVED}: {} must be an owner-owned regular file without group or world write; {ENDPOINT_REMEDY}",
            path.display()
        );
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("{ENDPOINT_UNRESOLVED}: read {}", path.display()))?;
    let endpoint = raw.trim().to_string();
    if endpoint.is_empty() || endpoint.chars().any(char::is_control) {
        bail!(
            "{ENDPOINT_UNRESOLVED}: {} must hold exactly one URL; {ENDPOINT_REMEDY}",
            path.display()
        );
    }
    Ok(endpoint)
}

/// The forward this host publishes for the canonical Skarbiec and the URL it
/// holds; `None` only when no forward file is there. A forward that is there
/// but is not the owner-only one-URL file is the error `canonical_endpoint`
/// names. Stado reads the fleet vault through this same file when its config
/// names no `secrets.skarbiec.url`, so the vault selection asks it too.
pub(crate) fn published_canonical_forward() -> Result<Option<(PathBuf, String)>> {
    let path = forwards_dir()?.join(CANONICAL_FORWARD);
    match fs::symlink_metadata(&path) {
        Ok(_) => Ok(Some((path, canonical_endpoint()?))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(anyhow::Error::new(error).context(format!(
            "{ENDPOINT_UNRESOLVED}: examine the canonical forward {}",
            path.display()
        ))),
    }
}

/// The canonical endpoint as it stands, without writing anything.
///
/// `doctor` needs the same three facts `endpoint declare` reports - which
/// file, which address, does it answer - and must not create a file while
/// diagnosing the absence of one.
pub(crate) fn canonical_endpoint_report() -> Result<Value> {
    let path = forwards_dir()?.join(CANONICAL_FORWARD);
    let endpoint = canonical_endpoint()?;
    let authority = endpoint_authority(&endpoint)?;
    let (answering, connect_error) = connect_probe(&authority);
    Ok(json!({
        "forward": path.display().to_string(),
        "endpoint": endpoint,
        "authority": authority,
        "answering": answering,
        "connect_error": connect_error,
    }))
}

/// What a connect probe announces it waits for.
const PROBE: &str = "a connection to the canonical Skarbiec";

/// Whether anything accepts a connection at `authority`, and the operating
/// system's refusal when nothing does. "Connection refused" and "permission
/// denied" call for different repairs, so the refusal is reported beside the
/// verdict.
fn connect_probe(authority: &str) -> (bool, Value) {
    let network = wait::Kind::Network;
    match wait::blocking(network, PROBE, authority, || TcpStream::connect(authority)) {
        Ok(_) => (true, Value::Null),
        Err(error) => (false, Value::String(error.to_string())),
    }
}

/// Write the canonical forward file this module reads.
///
/// Nothing in this product wrote it. The reader above enforces a precise
/// contract - owner-owned, no group or world write, exactly one URL - and
/// every fresh installation has no such file at all, so the first
/// `credential` call on a new machine failed with a path and no way to
/// produce it.
///
/// The declaration is verified through `canonical_endpoint` before returning,
/// so a file this command wrote can never be one the reader rejects.
pub(in crate::credential) fn declare_canonical_endpoint(endpoint: &str) -> Result<Value> {
    let endpoint = endpoint.trim();
    let directory = forwards_dir()?;
    let owner_only_directory = crate::core::mode::OWNER_ALL;
    fs::create_dir_all(&directory)
        .with_context(|| format!("create forwards directory {}", directory.display()))?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(owner_only_directory))
        .with_context(|| format!("protect forwards directory {}", directory.display()))?;
    let path = directory.join(CANONICAL_FORWARD);
    // Owner-only from its first byte, synced and renamed over the forward,
    // as every private file this product writes.
    crate::core::vault::atomic_write(&path, format!("{endpoint}\n").as_bytes())
        .with_context(|| format!("publish {}", path.display()))?;
    let declared = canonical_endpoint()?;
    let authority = endpoint_authority(&declared)?;
    // Whether anything answers is a separate question from whether the
    // declaration is well formed, and the report says both rather than
    // conflating them the way a bare connection error does.
    let (answering, connect_error) = connect_probe(&authority);
    Ok(json!({
        "forward": path.display().to_string(),
        "endpoint": declared,
        "authority": authority,
        "answering": answering,
        "connect_error": connect_error,
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

/// Whether a 409 reply names a stale service directory, read from its
/// `error_code` alone. The sentence beside it is for the person reading; a
/// reply that carries only a sentence is reported as the refusal it is.
pub(in crate::credential) fn stale_service_directory(value: &Value) -> bool {
    value.get("error_code").and_then(Value::as_str) == Some("service_directory_stale")
}
