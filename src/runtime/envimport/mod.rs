// `skarbiec env import <dotenv-file> --prefix <id-prefix> [--bindings <file>
// [--replace]] [--tags <tag,...>] [--yes]`: move the secrets a project keeps
// in a .env file into the vault. Each variable becomes a token item
// `<prefix>-<name in lower case, _ as ->` holding the value, named after the
// variable; with --bindings the file `skarbiec exec --env-from` reads is
// written beside it, NAME=<id>:token a line, so the program runs as before
// with the values in its environment and the .env can be deleted. Without
// --yes it lists what it would store and stores nothing. No value is printed.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::cli::args::{flag_set, OrUsage, Usage};
use crate::core::{schema, vault::Vault, vault_path};

mod dotenv;

const USAGE: &str =
    "usage: env import <dotenv-file> --prefix <id-prefix> [--bindings <file> [--replace]] [--tags <tag,...>] [--yes]";
/// The kind each value is stored as, and its one field: a bare secret value.
const KIND: &str = "token";
const FIELD: &str = "token";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    let Some(rest) = crate::cli::args::verb(command, positionals, "env", "import") else {
        return Ok(None);
    };
    let [source] = rest else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let prefix = flags.get("prefix").or_usage(USAGE)?;
    let here = std::env::current_dir().context("read the working directory")?;
    let source = here.join(source);
    let bindings = flags.get("bindings").map(|file| here.join(file));
    import(&source, prefix, bindings, flags).map(Some)
}

fn import(source: &PathBuf, prefix: &str, bindings: Option<PathBuf>, flags: &HashMap<String, String>) -> Result<Value> {
    let shown = source.display();
    let text = std::fs::read_to_string(source).with_context(|| format!("read {shown}"))?;
    let variables = dotenv::read(&text).with_context(|| format!("{shown}; nothing was stored"))?;
    if variables.is_empty() {
        bail!("{shown} sets no variable; nothing was stored");
    }
    let planned: Vec<(&dotenv::Variable, String)> = variables
        .iter()
        .map(|variable| (variable, format!("{prefix}-{}", variable.name.to_lowercase().replace('_', "-"))))
        .collect();
    for (variable, id) in &planned {
        if let Some((other, _)) = planned.iter().find(|(other, other_id)| other_id == id && other.name != variable.name) {
            bail!("{} and {} would both be stored as {id}; rename one in {shown}; nothing was stored", variable.name, other.name);
        }
    }
    let vault = Vault::open(vault_path())?;
    let taken: Vec<&str> = planned
        .iter()
        .map(|(_, id)| id.as_str())
        .filter(|id| vault.doc().get("items").and_then(|items| items.get(*id)).is_some())
        .collect();
    if !taken.is_empty() {
        bail!("{} already exist; env import never replaces an item. Choose another --prefix; nothing was stored", taken.join(", "));
    }
    if let Some(path) = &bindings {
        if path.exists() && !flag_set(flags, "replace") {
            bail!("{} already exists; add --replace to write the bindings over it; nothing was stored", path.display());
        }
    }
    let listed: Vec<Value> = planned
        .iter()
        .map(|(variable, id)| json!({"variable": variable.name, "line": variable.line, "item": id, "field": FIELD}))
        .collect();
    let bindings_shown = bindings.as_ref().map(|path| path.display().to_string());
    if !flag_set(flags, "yes") {
        return Ok(json!({"ok": true, "applied": false, "source": shown.to_string(), "items": listed, "bindings": bindings_shown}));
    }
    let mut stored: Vec<&str> = Vec::new();
    for (variable, id) in &planned {
        let mut fields = Map::new();
        fields.insert(FIELD.to_string(), json!(variable.value));
        let mut context = Map::new();
        context.insert(crate::core::items::DISPLAY_NAME.to_string(), json!(variable.name));
        let payload = schema::payload(KIND, fields, context)?;
        let mut write = HashMap::new();
        if let Some(tags) = flags.get("tags") {
            write.insert("tags".to_string(), tags.clone());
        }
        crate::cli::items::create_value(&write, id, &payload.to_string(), "env import").with_context(|| {
            format!("store {} (line {}) as {id}; stored before it: {}", variable.name, variable.line, stored.join(", "))
        })?;
        stored.push(id);
    }
    if let Some(path) = &bindings {
        let mut body = format!(
            "# The variables {shown} set, now kept in Skarbiec.\n# Run a program with them: skarbiec exec --env-from {} -- <program>\n",
            path.display()
        );
        for (variable, id) in &planned {
            body.push_str(&format!("{}={id}:{FIELD}\n", variable.name));
        }
        crate::core::vault::atomic_write(path, body.as_bytes())
            .with_context(|| format!("write the bindings {}; every item was stored: {}", path.display(), stored.join(", ")))?;
        crate::runtime::bindings::remember(path)?;
    }
    crate::runtime::audit::append(
        "env-imported",
        &json!({"source": shown.to_string(), "items": stored, "bindings": bindings_shown}),
    )?;
    Ok(json!({
        "ok": true,
        "applied": true,
        "source": shown.to_string(),
        "items": listed,
        "bindings": bindings_shown,
        "next": format!("{shown} still holds every value in plain text; delete it once the program runs through skarbiec exec"),
    }))
}
