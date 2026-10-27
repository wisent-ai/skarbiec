// `skarbiec ssh import <private-key-file> <id> [--name <display name>]
// [--tags <tag,...>] [--remove]`: move an SSH key that already sits in
// ~/.ssh into the vault, as a key-pair item ssh new would have made, so
// it is loaded with ssh add <id>, rotated with rotate --with ssh and backed up with
// the vault instead of living in a file. The public key is derived from the
// private one by ssh-keygen -y, so the pair stored always matches. With
// --remove the file and its .pub are deleted once the item reads back.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::cli::args::{flag_set, Usage};
use crate::core::{schema, vault::Vault, vault_path};

const USAGE: &str = "usage: ssh import <private-key-file> <id> [--name <display name>] [--tags <tag,...>] [--remove]";

pub(super) fn import(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let [file, id] = positionals else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let path = std::env::current_dir().context("read the working directory")?.join(file);
    {
        let vault = Vault::open(vault_path())?;
        if vault.doc().get("items").and_then(|items| items.get(id.as_str())).is_some() {
            bail!("{id} already exists; ssh import creates an item and never replaces one");
        }
    }
    let private_key = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    // -P "" answers a passphrase prompt with nothing, so a key kept under a
    // passphrase is refused instead of asking on a terminal nobody watches.
    let derived = stado_wait::output(Command::new("ssh-keygen").args(["-y", "-P", "", "-f"]).arg(&path))
        .context("run ssh-keygen, which reads the public half of the key")?;
    if !derived.status.success() {
        bail!(
            "ssh-keygen could not read {} ({}): {}; a key under a passphrase is stored without one after `ssh-keygen -p -f {}` takes it off",
            path.display(),
            derived.status,
            String::from_utf8_lossy(&derived.stderr).trim(),
            path.display()
        );
    }
    let public_key = String::from_utf8(derived.stdout).context("ssh-keygen printed a public key that is not UTF-8")?.trim().to_string();
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
    crate::cli::items::create_value(&write, id, &payload.to_string(), "ssh import")?;
    let stored = Vault::open(vault_path())?.get_item(id)?;
    if stored["fields"]["private_key"].as_str() != Some(private_key.as_str()) {
        bail!("{id} was written but does not read back the key from {}; the file is left in place", path.display());
    }
    let mut removed = Vec::new();
    if flag_set(flags, "remove") {
        let public_file = path.with_extension("pub");
        for gone in [path.as_path(), public_file.as_path()] {
            if remove(gone)? {
                removed.push(gone.display().to_string());
            }
        }
    }
    crate::runtime::audit::append("ssh-key-imported", &json!({"item": id, "from": path.display().to_string(), "removed": removed}))?;
    Ok(json!({"ok": true, "item": id, "public_key": public_key, "from": path.display().to_string(), "removed": removed}))
}

/// Delete one file; false when it was not there.
fn remove(path: &Path) -> Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("remove {} after storing it", path.display())),
    }
}
