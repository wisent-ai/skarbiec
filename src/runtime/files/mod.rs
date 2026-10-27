// Files kept in the vault: a recovery sheet, a licence key file, an SSH
// config, a provider's backup-code PDF. A file is stored as a `bundle` item
// holding `file_name` and `content_base64`, the shape the 1Password import
// already writes for an attachment, so an imported file and an attached one
// are read back the same way. The bytes are encrypted like any other value;
// they never pass through standard output.

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::core::{schema, vault::Vault, vault_path};

const FILE_NAME: &str = "file_name";
const CONTENT: &str = "content_base64";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "attach" => attach(flags, positionals).map(Some),
        "detach" => detach(positionals).map(Some),
        _ => Ok(None),
    }
}

/// The working directory's view of a path the caller named.
fn resolve(path: &str) -> Result<std::path::PathBuf> {
    Ok(std::env::current_dir()
        .context("the working directory cannot be read to place the file")?
        .join(path))
}

/// `attach <id> <file> [--tags <tag,...>]`: a new item holding the file.
/// An id that exists is refused; a file is never written over an item.
fn attach(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let [id, file, ..] = positionals else {
        return Err(crate::cli::args::Usage("usage: attach <id> <file> [--tags <tag,...>]".to_string()).into());
    };
    {
        let vault = Vault::open(vault_path())?;
        if vault.doc().get("items").and_then(|items| items.get(id.as_str())).is_some() {
            bail!("{id} already exists; attach creates an item and never replaces one");
        }
    }
    let source = resolve(file)?;
    let bytes = std::fs::read(&source).with_context(|| format!("read {}", source.display()))?;
    let file_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} names no file", source.display()))?
        .to_string();
    let fields = Map::from_iter([
        (FILE_NAME.to_string(), json!(file_name)),
        (CONTENT.to_string(), json!(base64::engine::general_purpose::STANDARD.encode(&bytes))),
    ]);
    let payload = schema::payload("bundle", fields, Map::new())?;
    let mut write = HashMap::new();
    if let Some(tags) = flags.get("tags") {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "attach")?;
    crate::runtime::audit::append("file-attached", &json!({"item": id, "file_name": file_name, "bytes": bytes.len()}))?;
    Ok(json!({"ok": true, "item": id, "file_name": file_name, "bytes": bytes.len()}))
}

/// `detach <id> <out-file>`: write the file an item holds, owner-only from
/// its first byte. An existing file is refused rather than replaced, because
/// the caller may not know what it would destroy.
fn detach(positionals: &[String]) -> Result<Value> {
    let [id, out, ..] = positionals else {
        return Err(crate::cli::args::Usage("usage: detach <id> <out-file>".to_string()).into());
    };
    let target = resolve(out)?;
    if crate::core::is_present(&target, "detach destination")? {
        bail!("{} already exists; name a path that does not, so nothing is overwritten", target.display());
    }
    let payload = Vault::open(vault_path())?.get_item(id)?;
    let fields = schema::fields(&payload)?;
    let encoded = fields
        .get(CONTENT)
        .and_then(Value::as_str)
        .with_context(|| format!("{id} holds no {CONTENT}; only an attached or imported file can be detached"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .with_context(|| format!("{id}'s {CONTENT} is not Base64"))?;
    crate::core::vault::atomic_write(&target, &bytes).with_context(|| format!("write {}", target.display()))?;
    crate::runtime::audit::append("file-detached", &json!({"item": id, "bytes": bytes.len()}))?;
    Ok(json!({
        "ok": true,
        "item": id,
        "file_name": fields.get(FILE_NAME),
        "out": out,
        "bytes": bytes.len(),
    }))
}
