// The gem adapter of `skarbiec tool`: RubyGems' push keys kept in
// plain text in gem's credentials file. `gem push` reads GEM_HOST_API_KEY
// from its environment before that file, so import stores one key —
// rubygems_api_key for rubygems.org, or a gem server's address for another —
// as a token item, binds GEM_HOST_API_KEY in the bindings file `exec
// --env-from` reads, and only then removes the key's line: `skarbiec exec
// --env-from <file> -- gem push <gem>` pushes from the vault. status names
// each key; never a value.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;

const FIELD: &str = "token";
/// The variable `gem push` reads its key from.
const VARIABLE: &str = "GEM_HOST_API_KEY";
const SEPARATOR: &str = ": ";

/// The credentials file gem reads: ~/.gem/credentials when ~/.gem exists,
/// else the one under $XDG_DATA_HOME/gem, or ~/.local/share/gem, as
/// RubyGems looks for it.
fn credentials_file() -> Result<PathBuf> {
    let home = crate::core::env::path("HOME")
        .context("HOME names no directory where gem keeps its credentials")?;
    let legacy = home.join(".gem");
    if crate::core::file_type(&legacy, "gem's ~/.gem directory")?.is_some_and(|kind| kind.is_dir())
    {
        return Ok(legacy.join("credentials"));
    }
    let data = match crate::core::env::path("XDG_DATA_HOME") {
        Some(data) => data,
        None => home.join(".local").join("share"),
    };
    Ok(data.join("gem").join("credentials"))
}

/// One `key: value` line of the credentials file: its position, the key as
/// gem names it — without the leading colon of a symbol or the quotes of an
/// address — and the value.
struct Kept {
    index: usize,
    key: String,
    value: String,
}

fn kept() -> Result<(PathBuf, String, Vec<Kept>)> {
    let file = credentials_file()?;
    let Some(text) = crate::core::read_present(&file, "gem's credentials")? else {
        return Ok((file, String::new(), Vec::new()));
    };
    let found = text
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let (key, value) = line.split_once(SEPARATOR)?;
            let key = key
                .trim()
                .trim_start_matches(':')
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
            let value = value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
            (!key.is_empty() && !value.is_empty()).then_some(Kept { index, key, value })
        })
        .collect();
    Ok((file, text, found))
}

/// Each key as tool status lists it.
pub(crate) fn status() -> Result<Value> {
    let (file, _, found) = kept()?;
    let entries: Vec<Value> = found
        .iter()
        .map(|entry| json!({"entry": entry.key, "kept": "plain text"}))
        .collect();
    Ok(json!({"file": file, "entries": entries, "variables": [VARIABLE]}))
}

pub(crate) fn import(request: &crate::runtime::tooltoken::Request) -> Result<Value> {
    let (id, bindings, tags) = (request.id, request.bindings, request.tags);
    let key = request.selected("gem server key")?;
    let (file, text, found) = kept()?;
    let Some(entry) = found.iter().find(|entry| entry.key == key) else {
        let known: Vec<&str> = found.iter().map(|entry| entry.key.as_str()).collect();
        bail!(
            "{} keeps no {key}; it keeps {}. Nothing was changed",
            file.display(),
            if known.is_empty() {
                "no key at all".to_string()
            } else {
                known.join(", ")
            }
        );
    };
    let binding = format!("{id}:{FIELD}");
    let updated = crate::runtime::npmcred::bound(bindings, &[(VARIABLE, &binding)])?;

    let mut fields = Map::new();
    fields.insert(FIELD.to_string(), json!(entry.value));
    let mut context = Map::new();
    context.insert(
        crate::core::items::DISPLAY_NAME.to_string(),
        json!(format!("RubyGems push key {key}")),
    );
    let payload = crate::core::schema::payload(FIELD, fields, context)?;
    let mut write = HashMap::from([("type".to_string(), FIELD.to_string())]);
    if let Some(tags) = tags {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "tool import")?;
    let read_back = crate::core::vault::Vault::open(crate::core::vault_path())?.get_item(id)?;
    if read_back["fields"][FIELD] != json!(entry.value) {
        bail!(
            "{id} does not read back {key}; {} was left as it was",
            file.display()
        );
    }

    if let Some(out) = updated {
        crate::core::vault::atomic_write(bindings, out.as_bytes()).with_context(|| {
            format!(
                "{} still keeps {key} and {id} holds a copy, but {} could not bind {VARIABLE}",
                file.display(),
                bindings.display()
            )
        })?;
    }
    crate::runtime::bindings::remember(bindings)?;
    let mut out: Vec<&str> = text
        .lines()
        .enumerate()
        .filter(|(index, _)| *index != entry.index)
        .map(|(_, line)| line)
        .collect();
    if text.ends_with('\n') {
        out.push("");
    }
    crate::core::vault::atomic_write(&file, out.join("\n").as_bytes()).with_context(|| {
        format!("{} still keeps {key}; {id} holds a copy and {} binds {VARIABLE}, so remove its line there", file.display(), bindings.display())
    })?;
    Ok(json!({
        "ok": true,
        "item": id,
        "entry": key,
        "variables": [VARIABLE],
        "file": file,
        "bindings": bindings,
        "run_with": format!("skarbiec exec --env-from {} -- gem push <gem>", bindings.display()),
        "next": format!("gem push reads {key} from {VARIABLE} now; run it through skarbiec exec, or it asks to sign in"),
    }))
}
