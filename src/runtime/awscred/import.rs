// `helper import aws <id> --profile <name> [--tags <tag,...>]`: move one
// profile's key out of the shared credentials file into the vault, and make
// the profile read it from there. The key is stored as a new access-key item
// and read back; then the profile's key lines are taken out of the
// credentials file — the section goes when nothing else is left in it — and
// setup points the profile's credential_process here. When setup is refused,
// the credentials file is written back as it was, so the profile keeps
// working either way; the item stays, named in the refusal.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use super::config;

const KEY_ID: &str = "aws_access_key_id";
const SECRET: &str = "aws_secret_access_key";
const TOKEN: &str = "aws_session_token";

/// The value `key` is set to among `lines`.
fn value(lines: &[&str], range: std::ops::Range<usize>, key: &str) -> Option<String> {
    range.into_iter().find_map(|index| {
        let (name, value) = lines[index].split_once('=')?;
        (name.trim() == key).then(|| value.trim().to_string())
    })
}

pub(super) fn import(id: &str, profile: &str, tags: Option<&String>) -> Result<Value> {
    let path = config::credentials_file()?;
    let original = config::read(&path)?;
    let lines: Vec<&str> = original.lines().collect();
    let header = format!("[{profile}]");
    let range = config::section(&lines, &header).with_context(|| format!("{} has no [{profile}] section to import", path.display()))?;
    let key = value(&lines, range.clone(), KEY_ID).with_context(|| format!("[{profile}] in {} keeps no {KEY_ID}", path.display()))?;
    let secret = value(&lines, range.clone(), SECRET).with_context(|| format!("[{profile}] in {} keeps no {SECRET}", path.display()))?;
    let token = value(&lines, range.clone(), TOKEN);

    // The item, refusing an id that exists, as set --if-absent does.
    let mut fields = serde_json::Map::new();
    fields.insert("access_key_id".to_string(), json!(key));
    fields.insert("secret_access_key".to_string(), json!(secret));
    if let Some(token) = &token {
        fields.insert("session_token".to_string(), json!(token));
    }
    let mut context = serde_json::Map::new();
    context.insert(crate::core::items::DISPLAY_NAME.to_string(), json!(format!("AWS profile {profile}")));
    let payload = crate::core::schema::payload("access-key", fields, context)?;
    let mut write = std::collections::HashMap::from([("type".to_string(), "access-key".to_string())]);
    if let Some(tags) = tags {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "helper import aws")?;
    let stored = crate::core::vault::Vault::open(crate::core::vault_path())?.get_item(id)?;
    if stored["fields"]["secret_access_key"] != json!(secret) {
        bail!("{id} does not read back the key from [{profile}]; {} was left as it was", path.display());
    }

    // The profile's key lines out; the header too when nothing else remains.
    let keys = [KEY_ID, SECRET, TOKEN];
    let kept: Vec<usize> = range.clone().filter(|&index| {
        let name = lines[index].split_once('=').map(|(name, _)| name.trim());
        !name.is_some_and(|name| keys.contains(&name)) && !lines[index].trim().is_empty()
    }).collect();
    let header_at = range.start.checked_sub(std::iter::once(()).count()).context("the section has no header line")?;
    let remaining: Vec<String> = lines
        .iter()
        .enumerate()
        .filter(|(index, _)| !range.contains(index) || kept.contains(index))
        .filter(|(index, _)| *index != header_at || !kept.is_empty())
        .map(|(_, line)| (*line).to_string())
        .collect();
    config::write(&path, &remaining)?;
    match config::setup(id, profile) {
        Ok(set) => {
            crate::runtime::audit::append("aws-credential-import", &json!({"item": id, "profile": profile, "key": key, "credentials": path}))?;
            Ok(json!({"ok": true, "item": id, "profile": profile, "key": key, "credentials": path, "config": set["config"], "line": set["line"]}))
        }
        Err(error) => {
            let restored = crate::core::vault::atomic_write(&path, original.as_bytes());
            match restored {
                Ok(()) => bail!("{error:#}; {} was written back as it was, so profile {profile} keeps its key there, and {id} holds a copy of it", path.display()),
                Err(undo) => bail!(
                    "{error:#}; {} could not be written back ({undo:#}): profile {profile}'s key is now only in {id}, and `skarbiec helper setup aws {id} --profile {profile}` points the profile at it",
                    path.display()
                ),
            }
        }
    }
}
