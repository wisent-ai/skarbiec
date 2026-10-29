// `skarbiec ssh new <id> [--comment <text>] [--name <display name>]
// [--tags <tag,...>]`: make an Ed25519 SSH key pair in the vault and store it
// as a key-pair item, printing only the public key to paste into a server's
// authorized_keys or a forge. The private key is written by ssh-keygen into
// an owner-only directory beside the vault file, read once into the item and
// removed with the directory before the answer, so it never reaches standard
// output, the clipboard or a shared temporary directory. `ssh add <id>` then
// loads it into an agent; `ssh import` and `ssh sign` are answered here too.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::args::Usage;
use crate::core::{clock, schema, vault::Vault, vault_path};

const USAGE: &str =
    "usage: ssh new <id> [--comment <text>] [--name <display name>] [--tags <tag,...>]";
/// The key type ssh-keygen makes: Ed25519, the one every current OpenSSH
/// server and forge accepts and the shortest to paste.
const KEY_TYPE: &str = "ed25519";

mod forges;
mod import;
mod push;
mod rotate;
pub(crate) use rotate::{rotate_item as rotate_ssh, USAGE as SSH_ROTATE_USAGE};
mod sign;

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if let Some(rest) = crate::cli::args::verb(command, positionals, "ssh", "sign") {
        return sign::sign(flags, rest).map(Some);
    }
    if let Some(rest) = crate::cli::args::verb(command, positionals, "ssh", "import") {
        return import::import(flags, rest).map(Some);
    }
    let Some(rest) = crate::cli::args::verb(command, positionals, "ssh", "new") else {
        return Ok(None);
    };
    let [id] = rest else {
        return Err(Usage(USAGE.to_string()).into());
    };
    make(id, flags).map(Some)
}

/// An owner-only directory beside the vault file, removed when dropped, so
/// the private key ssh-keygen writes — or a key file another provider's
/// client reads — is gone however the call ends.
pub(in crate::runtime) struct Workspace(pub(in crate::runtime) PathBuf);

impl Drop for Workspace {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!(
                "skarbiec: could not remove the key workspace {}: {error}",
                self.0.display()
            );
        }
    }
}

pub(in crate::runtime) fn workspace(vault: &Path) -> Result<Workspace> {
    let parent = vault.parent().with_context(|| {
        format!(
            "the vault path {} has no directory to work beside",
            vault.display()
        )
    })?;
    let path = parent.join(format!(
        ".skarbiec-keygen-{}-{}",
        clock::now_stamp(),
        std::process::id()
    ));
    std::fs::DirBuilder::new()
        .mode(crate::core::mode::OWNER_ALL)
        .create(&path)
        .with_context(|| format!("create the owner-only key workspace {}", path.display()))?;
    Ok(Workspace(path))
}

/// A fresh Ed25519 pair from ssh-keygen: the private key and the one-line
/// public key. ssh-keygen writes them into an owner-only workspace beside the
/// vault file, removed before this returns.
fn generate(comment: &str) -> Result<(String, String)> {
    let work = workspace(&vault_path())?;
    let key_file = work.0.join("key");
    let made = stado_wait::output(
        Command::new("ssh-keygen")
            .args(["-q", "-t", KEY_TYPE, "-N", "", "-C", comment, "-f"])
            .arg(&key_file),
    )
    .context("run ssh-keygen")?;
    if !made.status.success() {
        bail!(
            "ssh-keygen {}: {}; nothing was written",
            made.status,
            String::from_utf8_lossy(&made.stderr).trim()
        );
    }
    let private_key = std::fs::read_to_string(&key_file)
        .with_context(|| format!("read the key ssh-keygen wrote to {}", key_file.display()))?;
    let public_file = key_file.with_extension("pub");
    let public_key = std::fs::read_to_string(&public_file)
        .with_context(|| {
            format!(
                "read the public key ssh-keygen wrote to {}",
                public_file.display()
            )
        })?
        .trim()
        .to_string();
    drop(work);
    Ok((private_key, public_key))
}

fn make(id: &str, flags: &HashMap<String, String>) -> Result<Value> {
    {
        let vault = Vault::open(vault_path())?;
        if vault
            .doc()
            .get("items")
            .and_then(|items| items.get(id))
            .is_some()
        {
            bail!("{id} already exists; ssh new creates an item and never replaces one (rotate {id} --with ssh replaces its key)");
        }
    }
    let comment = match flags.get("comment") {
        Some(comment) => comment.clone(),
        None => id.to_string(),
    };
    let (private_key, public_key) = generate(&comment)?;
    let mut fields = Map::new();
    fields.insert("private_key".to_string(), json!(private_key));
    fields.insert("public_key".to_string(), json!(public_key));
    let mut context = Map::new();
    if let Some(name) = flags.get("name") {
        context.insert(crate::core::items::DISPLAY_NAME.to_string(), json!(name));
    }
    let payload = schema::payload("key-pair", fields, context)?;
    let mut write = HashMap::from([("type".to_string(), "key-pair".to_string())]);
    if let Some(tags) = flags.get("tags") {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "ssh new")?;
    crate::runtime::audit::append("ssh-key-created", &json!({"item": id, "type": KEY_TYPE}))?;
    Ok(json!({"ok": true, "item": id, "type": KEY_TYPE, "public_key": public_key}))
}
