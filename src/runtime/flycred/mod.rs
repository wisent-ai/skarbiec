// The fly adapter of `skarbiec tool`: flyctl's access token kept in
// ~/.fly/config.yml, where `fly auth login` keeps it in plain text. flyctl
// reads FLY_ACCESS_TOKEN from its environment before that file, so import
// stores the token as a token item, binds FLY_ACCESS_TOKEN in the bindings
// file `exec --env-from` reads, and only then removes the access_token line,
// leaving every other setting: `skarbiec exec --env-from <file> -- fly
// deploy` deploys from the vault. status says whether the file keeps a
// token; never the token.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;

const FIELD: &str = "token";
const VARIABLE: &str = "FLY_ACCESS_TOKEN";
const KEY: &str = "access_token:";
/// The entry status names the one token by.
const ENTRY: &str = "access_token";

/// flyctl's configuration: FLY_CONFIG_DIR/config.yml when set, else
/// ~/.fly/config.yml, as flyctl looks for it.
fn config_file() -> Result<PathBuf> {
    let directory = match crate::core::env::path("FLY_CONFIG_DIR") {
        Some(directory) => directory,
        None => crate::core::env::path("HOME")
            .context("neither FLY_CONFIG_DIR nor HOME names where flyctl keeps its configuration")?
            .join(".fly"),
    };
    Ok(directory.join("config.yml"))
}

/// The file, its text, and the access_token line's position and token.
fn kept() -> Result<(PathBuf, String, Option<(usize, String)>)> {
    let file = config_file()?;
    let Some(text) = crate::core::read_present(&file, "flyctl's config.yml")? else {
        return Ok((file, String::new(), None));
    };
    let found = text.lines().enumerate().find_map(|(index, line)| {
        let token = line
            .trim_start()
            .strip_prefix(KEY)?
            .trim()
            .trim_matches('"')
            .trim_matches('\'');
        (!token.is_empty()).then(|| (index, token.to_string()))
    });
    Ok((file, text, found))
}

/// The access token, when the file keeps one, as tool status lists it.
pub(crate) fn status() -> Result<Value> {
    let (file, _, found) = kept()?;
    let entries: Vec<Value> = found
        .iter()
        .map(|_| json!({"entry": ENTRY, "kept": "plain text"}))
        .collect();
    Ok(json!({"file": file, "entries": entries, "variables": [VARIABLE]}))
}

pub(crate) fn import(request: &crate::runtime::tooltoken::Request) -> Result<Value> {
    let (id, bindings, tags) = (request.id, request.bindings, request.tags);
    let (file, text, found) = kept()?;
    let Some((index, token)) = found else {
        bail!("{} keeps no access_token — flyctl may not be signed in here, or reads it from {VARIABLE} already; nothing was changed", file.display());
    };
    let binding = format!("{id}:{FIELD}");
    let updated = crate::runtime::npmcred::bound(bindings, &[(VARIABLE, &binding)])?;

    let mut fields = Map::new();
    fields.insert(FIELD.to_string(), json!(token));
    let mut context = Map::new();
    context.insert(
        crate::core::items::DISPLAY_NAME.to_string(),
        json!("Fly.io access token"),
    );
    let payload = crate::core::schema::payload(FIELD, fields, context)?;
    let mut write = HashMap::from([("type".to_string(), FIELD.to_string())]);
    if let Some(tags) = tags {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "tool import")?;
    let read_back = crate::core::vault::Vault::open(crate::core::vault_path())?.get_item(id)?;
    if read_back["fields"][FIELD] != json!(token) {
        bail!(
            "{id} does not read back the access token; {} was left as it was",
            file.display()
        );
    }
    if let Some(out) = updated {
        crate::core::vault::atomic_write(bindings, out.as_bytes())
            .with_context(|| format!("{} still keeps the access token and {id} holds a copy, but {} could not bind {VARIABLE}", file.display(), bindings.display()))?;
    }
    crate::runtime::bindings::remember(bindings)?;
    let mut out: Vec<&str> = text
        .lines()
        .enumerate()
        .filter(|(line, _)| *line != index)
        .map(|(_, line)| line)
        .collect();
    if text.ends_with('\n') {
        out.push("");
    }
    crate::core::vault::atomic_write(&file, out.join("\n").as_bytes()).with_context(|| {
        format!("{} still keeps the access token; {id} holds a copy and {} binds {VARIABLE}, so remove its access_token line there", file.display(), bindings.display())
    })?;
    Ok(json!({
        "ok": true,
        "item": id,
        "entry": ENTRY,
        "variables": [VARIABLE],
        "file": file,
        "bindings": bindings,
        "run_with": format!("skarbiec exec --env-from {} -- fly <command>", bindings.display()),
        "next": format!("flyctl reads its token from {VARIABLE} now; run it through skarbiec exec, or it is signed out"),
    }))
}
