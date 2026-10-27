// `helper import docker <id> <registry> --link <dir> [--tags <tag,...>]`:
// move the sign-in `docker login` left in config.json's auths — the username
// and password base64-encoded beside each other, readable by anything that
// reads the file — into a new login offered on the registry, then make Docker
// ask this vault for it (`setup`) and only then take it out of auths. When
// setup is refused, config.json keeps the sign-in and the item holds a copy,
// both named in the refusal.

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use super::config;

const AUTHS: &str = "auths";

pub(super) fn import(id: &str, registry: &str, link: &str, tags: Option<&String>) -> Result<Value> {
    let registry = crate::runtime::gitcred::checked_host(registry)?;
    let file = config::config_file()?;
    let members = config::read_config(&file)?;
    let encoded = members
        .get(AUTHS)
        .and_then(|auths| auths.get(registry))
        .and_then(|entry| entry.get("auth"))
        .and_then(Value::as_str)
        .with_context(|| format!("Docker's {} keeps no sign-in for {registry} under {AUTHS}; nothing was changed", file.display()))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .with_context(|| format!("{registry}'s sign-in in {} is not base64", file.display()))?;
    let decoded = String::from_utf8(decoded).with_context(|| format!("{registry}'s sign-in in {} is not text", file.display()))?;
    let (username, password) = decoded
        .split_once(':')
        .with_context(|| format!("{registry}'s sign-in in {} is not username:password", file.display()))?;

    let mut fields = Map::new();
    fields.insert("username".to_string(), json!(username));
    fields.insert("password".to_string(), json!(password));
    let mut context = Map::new();
    context.insert("domains".to_string(), json!([registry]));
    context.insert(crate::core::items::DISPLAY_NAME.to_string(), json!(format!("Docker registry {registry}")));
    let payload = crate::core::schema::payload("login", fields, context)?;
    let mut write = HashMap::from([("type".to_string(), "login".to_string())]);
    if let Some(tags) = tags {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "helper import docker")?;
    let stored = crate::core::vault::Vault::open(crate::core::vault_path())?.get_item(id)?;
    if stored["fields"]["password"] != json!(password) {
        bail!("{id} does not read back {registry}'s password; {} was left as it was", file.display());
    }

    let set = config::setup(registry, link).with_context(|| {
        format!("{} still keeps {registry}'s sign-in under {AUTHS}, and {id} holds a copy of it", file.display())
    })?;
    // Read again: setup has just written credHelpers into the same file.
    let mut members = config::read_config(&file)?;
    let removed = members.get_mut(AUTHS).and_then(Value::as_object_mut).and_then(|auths| auths.remove(registry));
    if removed.is_none() {
        bail!("{registry}'s sign-in left {}'s {AUTHS} while it was imported; {id} holds it and Docker asks this vault for it", file.display());
    }
    config::write_config(&file, members).with_context(|| {
        format!("Docker asks this vault for {registry} now, but its sign-in is still under {AUTHS} in {}; remove it there", file.display())
    })?;
    crate::runtime::audit::append("docker-credential-import", &json!({"item": id, "registry": registry, "config": file}))?;
    Ok(json!({
        "ok": true,
        "item": id,
        "registry": registry,
        "username": username,
        "config": file,
        "program": set["program"],
    }))
}
