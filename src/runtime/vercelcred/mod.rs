// The vercel adapter of `skarbiec tool`: the Vercel CLI's token kept
// in its auth.json, where `vercel login` keeps it in plain text. The CLI
// reads VERCEL_TOKEN from its environment, so import stores the token as a
// token item, binds VERCEL_TOKEN in the bindings file `exec --env-from`
// reads, and only then writes auth.json back without the token, keeping
// every other key: `skarbiec exec --env-from <file> -- vercel deploy`
// deploys from the vault, and `rotate <id> --with vercel` can replace
// that same item's token. status says which auth.json the CLI reads and
// whether it keeps a token; never the token.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;

const FIELD: &str = "token";
const VARIABLE: &str = "VERCEL_TOKEN";
const KEY: &str = "token";
const APP: &str = "com.vercel.cli";

/// The auth.json files the CLI may read, in the order it looks: its data
/// directory — ~/Library/Application Support on macOS, $XDG_DATA_HOME or
/// ~/.local/share elsewhere — then the older ~/.vercel.
fn candidates() -> Result<Vec<PathBuf>> {
    let home = crate::core::env::path("HOME")
        .context("HOME names no directory where the Vercel CLI keeps auth.json")?;
    let mut found = Vec::new();
    if cfg!(target_os = "macos") {
        found.push(home.join("Library").join("Application Support").join(APP));
    }
    if let Some(data) = crate::core::env::path("XDG_DATA_HOME") {
        found.push(data.join(APP));
    }
    found.push(home.join(".local").join("share").join(APP));
    found.push(home.join(".vercel"));
    Ok(found
        .into_iter()
        .map(|directory| directory.join("auth.json"))
        .collect())
}

/// The auth.json the CLI reads — the first that exists, else the first it
/// would write — with its JSON when it exists.
fn auth() -> Result<(PathBuf, Option<Map<String, Value>>)> {
    let candidates = candidates()?;
    for file in &candidates {
        if let Some(text) = crate::core::read_present(file, "the Vercel CLI's auth.json")? {
            let parsed: Map<String, Value> = serde_json::from_str(&text).with_context(|| {
                format!(
                    "{} is not the JSON object the Vercel CLI writes",
                    file.display()
                )
            })?;
            return Ok((file.clone(), Some(parsed)));
        }
    }
    let first = candidates
        .into_iter()
        .next()
        .context("no place the Vercel CLI keeps auth.json")?;
    Ok((first, None))
}

fn token_of(parsed: &Option<Map<String, Value>>) -> Option<String> {
    parsed
        .as_ref()?
        .get(KEY)?
        .as_str()
        .filter(|token| !token.is_empty())
        .map(str::to_string)
}

/// The token, when auth.json keeps one, as tool status lists it.
pub(crate) fn status() -> Result<Value> {
    let (file, parsed) = auth()?;
    let entries: Vec<Value> = token_of(&parsed)
        .iter()
        .map(|_| json!({"entry": KEY, "kept": "plain text"}))
        .collect();
    Ok(json!({"file": file, "entries": entries, "variables": [VARIABLE]}))
}

pub(crate) fn import(request: &crate::runtime::tooltoken::Request) -> Result<Value> {
    let (id, bindings, tags) = (request.id, request.bindings, request.tags);
    let (file, parsed) = auth()?;
    let Some(token) = token_of(&parsed) else {
        bail!(
            "{} keeps no token — the Vercel CLI may not be signed in here; nothing was changed",
            file.display()
        );
    };
    let binding = format!("{id}:{FIELD}");
    let updated = crate::runtime::npmcred::bound(bindings, &[(VARIABLE, &binding)])?;

    let mut fields = Map::new();
    fields.insert(FIELD.to_string(), json!(token));
    let mut context = Map::new();
    context.insert(
        crate::core::items::DISPLAY_NAME.to_string(),
        json!("Vercel CLI token"),
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
            "{id} does not read back the token; {} was left as it was",
            file.display()
        );
    }
    if let Some(out) = updated {
        crate::core::vault::atomic_write(bindings, out.as_bytes()).with_context(|| {
            format!(
                "{} still keeps the token and {id} holds a copy, but {} could not bind {VARIABLE}",
                file.display(),
                bindings.display()
            )
        })?;
    }
    crate::runtime::bindings::remember(bindings)?;
    let mut rest = parsed.context("auth.json was read with a token, so it holds an object")?;
    rest.remove(KEY);
    let body = serde_json::to_vec_pretty(&rest).context("render auth.json without the token")?;
    crate::core::vault::atomic_write(&file, &body).with_context(|| {
        format!("{} still keeps the token; {id} holds a copy and {} binds {VARIABLE}, so remove its token there", file.display(), bindings.display())
    })?;
    Ok(json!({
        "ok": true,
        "item": id,
        "entry": KEY,
        "variables": [VARIABLE],
        "file": file,
        "bindings": bindings,
        "run_with": format!("skarbiec exec --env-from {} -- vercel <command>", bindings.display()),
        "rotate_with": format!("skarbiec rotate {id} --with vercel"),
        "next": format!("the Vercel CLI reads its token from {VARIABLE} now; run it through skarbiec exec, or it is signed out"),
    }))
}
