// The twine adapter of `skarbiec tool`: twine's upload passwords kept
// in ~/.pypirc. twine reads TWINE_USERNAME and TWINE_PASSWORD from its
// environment before the file, so import moves one repository section's
// username and password into a login item, binds both variables in the
// bindings file `exec --env-from` reads, and only then removes the password
// line: `skarbiec exec --env-from <file> -- twine upload -r <name> dist/*`
// signs in from the vault, and nothing on disk holds the password. status
// names each section and whether it still keeps a password; never a value.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;

const USERNAME: &str = "username";
const PASSWORD: &str = "password";
/// The variables twine reads its sign-in from.
const USER_VARIABLE: &str = "TWINE_USERNAME";
const PASSWORD_VARIABLE: &str = "TWINE_PASSWORD";

/// The file twine reads by default: ~/.pypirc.
fn pypirc() -> Result<PathBuf> {
    Ok(crate::core::env::path("HOME").context("HOME names no directory where twine keeps ~/.pypirc")?.join(".pypirc"))
}

/// One `[section]` of .pypirc: its name, and each `key = value` line with
/// its position, so import can take one line out and keep the rest.
pub(crate) struct Section {
    pub(crate) name: String,
    lines: Vec<(usize, String, String)>,
}

impl Section {
    fn value(&self, key: &str) -> Option<&str> {
        self.lines.iter().find(|(_, held, _)| held == key).map(|(_, _, value)| value.as_str())
    }
    pub(crate) fn keeps_password(&self) -> bool {
        self.value(PASSWORD).is_some_and(|value| !value.is_empty())
    }
}

/// The sections of .pypirc, or none when there is no file.
pub(crate) fn sections() -> Result<(PathBuf, String, Vec<Section>)> {
    let file = pypirc()?;
    let Some(text) = crate::core::read_present(&file, "twine's ~/.pypirc")? else {
        return Ok((file, String::new(), Vec::new()));
    };
    let mut found: Vec<Section> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
            found.push(Section { name: name.trim().to_string(), lines: Vec::new() });
        } else if let (Some(section), Some((key, value))) = (found.last_mut(), trimmed.split_once('=')) {
            section.lines.push((index, key.trim().to_string(), value.trim().to_string()));
        }
    }
    Ok((file, text, found))
}

/// Each repository section as tool status lists it.
pub(crate) fn status() -> Result<Value> {
    let (file, _, found) = sections()?;
    let entries: Vec<Value> = found
        .iter()
        .filter(|section| section.name != "distutils")
        .map(|section| match section.keeps_password() {
            true => json!({"entry": section.name, "kept": "plain text"}),
            false => json!({"entry": section.name, "kept": "no password"}),
        })
        .collect();
    Ok(json!({"file": file, "entries": entries, "variables": [USER_VARIABLE, PASSWORD_VARIABLE]}))
}

pub(crate) fn import(request: &crate::runtime::tooltoken::Request) -> Result<Value> {
    let (id, bindings, tags) = (request.id, request.bindings, request.tags);
    let repository = request.selected("repository section")?;
    let (file, text, found) = sections()?;
    let Some(section) = found.iter().find(|section| section.name == repository) else {
        bail!("{} has no [{repository}] section; nothing was changed", file.display());
    };
    let Some(password) = section.value(PASSWORD).filter(|value| !value.is_empty()) else {
        bail!("[{repository}] in {} keeps no password; nothing was changed", file.display());
    };
    let username = section
        .value(USERNAME)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("[{repository}] in {} names no username for the password; add `username = __token__` for an API token", file.display()))?;
    let user_binding = format!("{id}:{USERNAME}");
    let password_binding = format!("{id}:{PASSWORD}");
    let updated = crate::runtime::npmcred::bound(bindings, &[(USER_VARIABLE, &user_binding), (PASSWORD_VARIABLE, &password_binding)])?;

    let mut fields = Map::new();
    fields.insert(USERNAME.to_string(), json!(username));
    fields.insert(PASSWORD.to_string(), json!(password));
    let mut context = Map::new();
    context.insert(crate::core::items::DISPLAY_NAME.to_string(), json!(format!("twine upload to {repository}")));
    let payload = crate::core::schema::payload("login", fields, context)?;
    let mut write = HashMap::from([("type".to_string(), "login".to_string())]);
    if let Some(tags) = tags {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "tool import")?;
    let read_back = crate::core::vault::Vault::open(crate::core::vault_path())?.get_item(id)?;
    if read_back["fields"][PASSWORD] != json!(password) {
        bail!("{id} does not read back [{repository}]'s password; {} was left as it was", file.display());
    }

    if let Some(out) = updated {
        crate::core::vault::atomic_write(bindings, out.as_bytes())
            .with_context(|| format!("{} still keeps [{repository}]'s password and {id} holds a copy, but {} could not bind it", file.display(), bindings.display()))?;
    }
    crate::runtime::bindings::remember(bindings)?;
    let drop: Vec<usize> = section.lines.iter().filter(|(_, key, _)| key == PASSWORD).map(|(index, _, _)| *index).collect();
    let mut out: Vec<&str> = text.lines().enumerate().filter(|(index, _)| !drop.contains(index)).map(|(_, line)| line).collect();
    if text.ends_with('\n') {
        out.push("");
    }
    crate::core::vault::atomic_write(&file, out.join("\n").as_bytes()).with_context(|| {
        format!("{} still keeps [{repository}]'s password; {id} holds a copy and {} binds it, so remove the password line there", file.display(), bindings.display())
    })?;
    Ok(json!({
        "ok": true,
        "item": id,
        "entry": repository,
        "file": file,
        "bindings": bindings,
        "variables": [USER_VARIABLE, PASSWORD_VARIABLE],
        "run_with": format!("skarbiec exec --env-from {} -- twine upload -r {repository} dist/*", bindings.display()),
        "next": format!("twine reads [{repository}]'s password from {PASSWORD_VARIABLE} now; run it through skarbiec exec, or it asks for one"),
    }))
}
