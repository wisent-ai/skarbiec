// `tool import npm <id> --select <//host/path/> --bindings
// <file>`: move one registry's plain-text `_authToken` out of npm's user
// configuration into a new token item. The bindings file gains
// `NAME=<id>:token` before .npmrc changes, and .npmrc's line becomes
// `//host/path/:_authToken=${NAME}`, which npm fills from its environment —
// the environment `skarbiec exec --env-from <file>` gives it. When .npmrc
// cannot be written, it keeps the token and the item holds a copy, both
// named in the refusal.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::Path;

const KIND: &str = "token";
const FIELD: &str = "token";
const PREFIX: &str = "NPM_TOKEN_";

/// The variable a registry's token is read from: NPM_TOKEN_ and the
/// registry's letters and digits in upper case, every other run of
/// characters one underscore.
fn variable(registry: &str) -> String {
    let mut name = PREFIX.to_string();
    for c in registry.chars() {
        match c.is_ascii_alphanumeric() {
            true => name.push(c.to_ascii_uppercase()),
            false if !name.ends_with('_') => name.push('_'),
            false => {}
        }
    }
    name.trim_end_matches('_').to_string()
}

/// The bindings file `exec --env-from` reads with each `(name, binding)`
/// bound: None when every one already is, refused when a name is bound to
/// something else; a file not there yet is written holding the lines. Other
/// package tools moving a token into the vault bind it the same way.
pub(crate) fn bound(file: &Path, pairs: &[(&str, &str)]) -> Result<Option<String>> {
    let mut text = match crate::core::read_present(file, "bindings file")? {
        Some(text) => text,
        None => String::new(),
    };
    let mut changed = false;
    for (name, binding) in pairs {
        let line = format!("{name}={binding}");
        let start = format!("{name}=");
        match text
            .lines()
            .find(|kept| kept.trim_start().starts_with(&start))
        {
            Some(kept) if kept.trim() == line => {}
            Some(kept) => bail!(
                "{} already binds {name} as {}; give another --bindings file or remove that line",
                file.display(),
                kept.trim()
            ),
            None => {
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str(&line);
                text.push('\n');
                changed = true;
            }
        }
    }
    Ok(changed.then_some(text))
}

pub(crate) fn import(request: &crate::runtime::tooltoken::Request) -> Result<Value> {
    let (id, bindings, tags) = (request.id, request.bindings, request.tags);
    let registry = request.selected("registry")?;
    if !registry.starts_with("//") {
        bail!("--select {registry} is not a registry key as .npmrc writes it, such as //registry.npmjs.org/");
    }
    let (npmrc, found) = super::signins()?;
    let Some(signin) = found.into_iter().find(|signin| signin.registry == registry) else {
        bail!(
            "{} keeps no _authToken for {registry}; nothing was changed",
            npmrc.display()
        );
    };
    if let Some(name) = signin.reference() {
        bail!(
            "{} already reads {registry}'s token from ${{{name}}}; nothing was changed",
            npmrc.display()
        );
    }
    let name = variable(registry);
    let binding = format!("{id}:{FIELD}");
    let updated = bound(bindings, &[(name.as_str(), binding.as_str())])?;

    let mut fields = Map::new();
    fields.insert(FIELD.to_string(), json!(signin.token));
    let mut context = Map::new();
    context.insert(
        crate::core::items::DISPLAY_NAME.to_string(),
        json!(format!("npm token for {registry}")),
    );
    let payload = crate::core::schema::payload(KIND, fields, context)?;
    let mut write = HashMap::from([("type".to_string(), KIND.to_string())]);
    if let Some(tags) = tags {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "tool import")?;
    let read_back = crate::core::vault::Vault::open(crate::core::vault_path())?.get_item(id)?;
    if read_back["fields"][FIELD] != json!(signin.token) {
        bail!(
            "{id} does not read back {registry}'s token; {} was left as it was",
            npmrc.display()
        );
    }

    if let Some(out) = updated {
        crate::core::vault::atomic_write(bindings, out.as_bytes()).with_context(|| {
            format!("{} still keeps {registry}'s token and {id} holds a copy, but {} could not bind {name}", npmrc.display(), bindings.display())
        })?;
    }
    crate::runtime::bindings::remember(bindings)?;
    let text = std::fs::read_to_string(&npmrc)
        .with_context(|| format!("read {} again", npmrc.display()))?;
    let replaced = format!("{registry}:_authToken=${{{name}}}");
    let mut out: Vec<&str> = text
        .lines()
        .map(|line| {
            if line == signin.line {
                replaced.as_str()
            } else {
                line
            }
        })
        .collect();
    if text.ends_with('\n') {
        out.push("");
    }
    crate::core::vault::atomic_write(&npmrc, out.join("\n").as_bytes()).with_context(|| {
        format!(
            "{} still keeps {registry}'s token; {id} holds a copy and {} binds {name} to it, so replace the token there with ${{{name}}}",
            npmrc.display(),
            bindings.display()
        )
    })?;
    Ok(json!({
        "ok": true,
        "item": id,
        "entry": registry,
        "variables": [name],
        "file": npmrc,
        "bindings": bindings,
        "run_with": format!("skarbiec exec --env-from {} -- npm <command>", bindings.display()),
        "next": format!("npm now reads {registry}'s token from {name}; run it through skarbiec exec, or it signs in without one"),
    }))
}
