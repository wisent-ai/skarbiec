// The npm adapter of `skarbiec tool`: npm's registry tokens kept in
// plain text. npm has no credential helper, but it reads `${NAME}` in .npmrc
// from its environment, so import moves one registry's `_authToken` into a
// token item, writes `${NAME}` in its place, and adds `NAME=<id>:token` to a
// bindings file `exec --env-from` reads: `skarbiec exec --env-from <file> --
// npm publish` then signs in with the token from the vault, and nothing on
// disk holds it. status names each registry's sign-in and whether it is kept
// in plain text, an environment reference or a password; never a token.

mod import;
pub(crate) use import::{bound, import};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::PathBuf;

/// The .npmrc key holding a registry's bearer token.
const TOKEN_KEY: &str = ":_authToken=";

/// The user configuration npm reads: $NPM_CONFIG_USERCONFIG, else ~/.npmrc.
pub(crate) fn npmrc() -> Result<PathBuf> {
    match crate::core::env::path("NPM_CONFIG_USERCONFIG") {
        Some(file) => Ok(file),
        None => Ok(crate::core::env::path("HOME").context("HOME names no directory where npm keeps ~/.npmrc")?.join(".npmrc")),
    }
}

/// One registry sign-in line: the registry key (`//host/path/`), how its
/// token is kept, and the line itself for import to replace.
pub(crate) struct Signin {
    pub(crate) registry: String,
    pub(crate) token: String,
    pub(crate) line: String,
}

impl Signin {
    /// The environment variable the token is read from, when the line
    /// names one as npm expands it.
    pub(crate) fn reference(&self) -> Option<&str> {
        self.token.strip_prefix("${").and_then(|rest| rest.strip_suffix('}'))
    }
}

/// Every `//registry/:_authToken=` line the user configuration holds.
pub(crate) fn signins() -> Result<(PathBuf, Vec<Signin>)> {
    let file = npmrc()?;
    let Some(text) = crate::core::read_present(&file, "npm's user configuration")? else {
        return Ok((file, Vec::new()));
    };
    let found = text
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (registry, token) = trimmed.split_once(TOKEN_KEY)?;
            registry.starts_with("//").then(|| Signin {
                registry: registry.to_string(),
                token: token.trim().trim_matches('"').to_string(),
                line: line.to_string(),
            })
        })
        .collect();
    Ok((file, found))
}

/// Each registry sign-in as tool status lists it: the registry as the
/// entry, kept in plain text or read from an environment variable.
pub(crate) fn status() -> Result<Value> {
    let (file, found) = signins()?;
    let entries: Vec<Value> = found
        .iter()
        .map(|signin| match signin.reference() {
            Some(name) => json!({"entry": signin.registry, "kept": "environment", "variable": name}),
            None => json!({"entry": signin.registry, "kept": "plain text"}),
        })
        .collect();
    Ok(json!({"file": file, "entries": entries}))
}
