// The huggingface adapter of `skarbiec tool`: Hugging Face access
// tokens kept in the plain-text files `hf auth login` writes — the active
// token and the named stored tokens. huggingface_hub, transformers, datasets
// and the hf CLI read HF_TOKEN from their environment before either file, so
// import stores one token as a token item, binds HF_TOKEN in the bindings
// file `exec --env-from` reads, and only then removes every plain copy of
// that token: the active token file when it holds it, and each stored token
// holding it. `skarbiec exec --env-from <file> -- python train.py` signs in
// from the vault. status names the active token and each stored one; never
// a token.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const FIELD: &str = "token";
const VARIABLE: &str = "HF_TOKEN";
const STORED_KEY: &str = "hf_token";
const PLAIN: &str = "plain text";
/// The entry status names the token file's token by.
const ACTIVE: &str = "active";

/// The active token file and the stored tokens file, where huggingface_hub
/// looks for them: HF_TOKEN_PATH and HF_STORED_TOKENS_PATH, else under
/// HF_HOME, else $XDG_CACHE_HOME/huggingface, else ~/.cache/huggingface.
fn files() -> Result<(PathBuf, PathBuf)> {
    let home = match crate::core::env::path("HF_HOME") {
        Some(home) => home,
        None => match crate::core::env::path("XDG_CACHE_HOME") {
            Some(cache) => cache.join("huggingface"),
            None => crate::core::env::path("HOME")
                .context("neither HF_HOME nor HOME names where Hugging Face keeps its token")?
                .join(".cache")
                .join("huggingface"),
        },
    };
    let active = match crate::core::env::path("HF_TOKEN_PATH") {
        Some(path) => path,
        None => home.join("token"),
    };
    let stored = match crate::core::env::path("HF_STORED_TOKENS_PATH") {
        Some(path) => path,
        None => home.join("stored_tokens"),
    };
    Ok((active, stored))
}

/// One `[name]` section of stored_tokens: its name, its first line and its
/// last, and the token its hf_token line holds.
struct Stored {
    name: String,
    lines: std::ops::Range<usize>,
    token: String,
}

fn stored(text: &str) -> Vec<Stored> {
    let mut found: Vec<Stored> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            found.push(Stored {
                name: name.to_string(),
                lines: index..index,
                token: String::new(),
            });
        } else if let Some(section) = found.last_mut() {
            if let Some((key, value)) = trimmed.split_once('=') {
                if key.trim() == STORED_KEY {
                    section.token = value.trim().to_string();
                }
            }
        }
        if let Some(section) = found.last_mut() {
            section.lines.end = index + std::iter::once(()).count();
        }
    }
    found
        .into_iter()
        .filter(|section| !section.token.is_empty())
        .collect()
}

fn read(path: &Path, what: &str) -> Result<String> {
    Ok(match crate::core::read_present(path, what)? {
        Some(text) => text,
        None => String::new(),
    })
}

/// The active token and each stored one as tool status lists them;
/// the active one is imported without --select.
pub(crate) fn status() -> Result<Value> {
    let (active_file, stored_file) = files()?;
    let active = read(&active_file, "the Hugging Face token")?;
    let mut entries: Vec<Value> = Vec::new();
    if !active.trim().is_empty() {
        entries.push(json!({"entry": ACTIVE, "kept": PLAIN, "selected": false}));
    }
    for section in stored(&read(&stored_file, "Hugging Face's stored tokens")?) {
        entries.push(json!({"entry": section.name, "kept": PLAIN}));
    }
    Ok(
        json!({"file": active_file, "stored_file": stored_file, "entries": entries, "variables": [VARIABLE]}),
    )
}

pub(crate) fn import(request: &crate::runtime::tooltoken::Request) -> Result<Value> {
    let (id, name, bindings, tags) = (request.id, request.select, request.bindings, request.tags);
    let (active_file, stored_file) = files()?;
    let active = read(&active_file, "the Hugging Face token")?
        .trim()
        .to_string();
    let stored_text = read(&stored_file, "Hugging Face's stored tokens")?;
    let sections = stored(&stored_text);
    let token = match name {
        Some(name) => match sections.iter().find(|section| section.name == name) {
            Some(section) => section.token.clone(),
            None => bail!(
                "{} keeps no token named {name}; nothing was changed",
                stored_file.display()
            ),
        },
        None if active.is_empty() => bail!(
            "{} holds no active token; name a stored one with --select; nothing was changed",
            active_file.display()
        ),
        None => active.clone(),
    };
    let binding = format!("{id}:{FIELD}");
    let updated = crate::runtime::npmcred::bound(bindings, &[(VARIABLE, &binding)])?;

    let mut fields = Map::new();
    fields.insert(FIELD.to_string(), json!(token));
    let mut context = Map::new();
    let shown = match name {
        Some(name) => format!("Hugging Face token {name}"),
        None => "Hugging Face token".to_string(),
    };
    context.insert(crate::core::items::DISPLAY_NAME.to_string(), json!(shown));
    let payload = crate::core::schema::payload(FIELD, fields, context)?;
    let mut write = HashMap::from([("type".to_string(), FIELD.to_string())]);
    if let Some(tags) = tags {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "tool import")?;
    let read_back = crate::core::vault::Vault::open(crate::core::vault_path())?.get_item(id)?;
    if read_back["fields"][FIELD] != json!(token) {
        bail!("{id} does not read back the token; the Hugging Face files were left as they were");
    }
    if let Some(out) = updated {
        crate::core::vault::atomic_write(bindings, out.as_bytes())
            .with_context(|| format!("the Hugging Face files still keep the token and {id} holds a copy, but {} could not bind {VARIABLE}", bindings.display()))?;
    }
    crate::runtime::bindings::remember(bindings)?;

    // Every plain copy of this token goes: the active file when it holds it,
    // and each stored section holding it.
    let mut removed: Vec<String> = Vec::new();
    let held: Vec<&Stored> = sections
        .iter()
        .filter(|section| section.token == token)
        .collect();
    if !held.is_empty() {
        let mut out: Vec<&str> = stored_text
            .lines()
            .enumerate()
            .filter(|(index, _)| !held.iter().any(|section| section.lines.contains(index)))
            .map(|(_, line)| line)
            .collect();
        if stored_text.ends_with('\n') {
            out.push("");
        }
        crate::core::vault::atomic_write(&stored_file, out.join("\n").as_bytes()).with_context(|| {
            format!("{} still keeps the token; {id} holds a copy and {} binds {VARIABLE}, so remove it there", stored_file.display(), bindings.display())
        })?;
        removed.extend(
            held.iter()
                .map(|section| format!("{} [{}]", stored_file.display(), section.name)),
        );
    }
    if active == token {
        std::fs::remove_file(&active_file).with_context(|| {
            format!("{} still keeps the token; {id} holds a copy and {} binds {VARIABLE}, so remove the file", active_file.display(), bindings.display())
        })?;
        removed.push(active_file.display().to_string());
    }
    Ok(json!({
        "ok": true,
        "item": id,
        "entry": match name {
            Some(name) => name,
            None => ACTIVE,
        },
        "variables": [VARIABLE],
        "file": active_file,
        "removed": removed,
        "bindings": bindings,
        "run_with": format!("skarbiec exec --env-from {} -- <program>", bindings.display()),
        "next": format!("huggingface_hub reads the token from {VARIABLE} now; run programs through skarbiec exec, or they are signed out"),
    }))
}
