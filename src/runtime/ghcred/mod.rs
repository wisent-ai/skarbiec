// The gh adapter of `skarbiec tool`: the GitHub CLI's token kept in
// hosts.yml, where gh keeps it in plain text when no system keyring took it.
// gh reads GH_TOKEN (GH_ENTERPRISE_TOKEN for a GitHub Enterprise host)
// before hosts.yml, so import stores the host's oauth_token as a token item,
// binds that variable in the bindings file `exec --env-from` reads, and only
// then removes the host's oauth_token lines: `skarbiec exec --env-from <file>
// -- gh pr list` signs in from the vault. status names each host and whether
// its token is in plain text; never a token.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;

const KEY: &str = "oauth_token:";
const FIELD: &str = "token";
const PUBLIC_HOST: &str = "github.com";
const PUBLIC_VARIABLE: &str = "GH_TOKEN";
const ENTERPRISE_VARIABLE: &str = "GH_ENTERPRISE_TOKEN";

/// gh's hosts.yml: in GH_CONFIG_DIR, else $XDG_CONFIG_HOME/gh, else
/// ~/.config/gh, as gh looks for it.
fn hosts_file() -> Result<PathBuf> {
    if let Some(dir) = crate::core::env::path("GH_CONFIG_DIR") {
        return Ok(dir.join("hosts.yml"));
    }
    let config = match crate::core::env::path("XDG_CONFIG_HOME") {
        Some(dir) => dir,
        None => crate::core::env::path("HOME")
            .context("HOME names no directory where gh keeps its configuration")?
            .join(".config"),
    };
    Ok(config.join("gh").join("hosts.yml"))
}

/// One host block of hosts.yml: the host, and the lines holding a token
/// within it, by position and value.
struct Host {
    name: String,
    tokens: Vec<(usize, String)>,
}

fn hosts() -> Result<(PathBuf, String, Vec<Host>)> {
    let file = hosts_file()?;
    let Some(text) = crate::core::read_present(&file, "gh's hosts.yml")? else {
        return Ok((file, String::new(), Vec::new()));
    };
    let mut found: Vec<Host> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let indented = line.starts_with(char::is_whitespace);
        if !indented && line.trim_end().ends_with(':') {
            found.push(Host {
                name: line.trim_end().trim_end_matches(':').to_string(),
                tokens: Vec::new(),
            });
        } else if let (true, Some(host), Some(token)) =
            (indented, found.last_mut(), line.trim().strip_prefix(KEY))
        {
            let token = token.trim().trim_matches('"').to_string();
            if !token.is_empty() {
                host.tokens.push((index, token));
            }
        }
    }
    Ok((file, text, found))
}

fn variable(host: &str) -> &'static str {
    if host == PUBLIC_HOST {
        PUBLIC_VARIABLE
    } else {
        ENTERPRISE_VARIABLE
    }
}

/// Each host as tool status lists it.
pub(crate) fn status() -> Result<Value> {
    let (file, _, found) = hosts()?;
    let entries: Vec<Value> = found
        .iter()
        .map(|host| if host.tokens.is_empty() {
            json!({"entry": host.name, "kept": "no token here", "variable": variable(&host.name)})
        } else {
            json!({"entry": host.name, "kept": "plain text", "variable": variable(&host.name)})
        })
        .collect();
    Ok(json!({"file": file, "entries": entries}))
}

pub(crate) fn import(request: &crate::runtime::tooltoken::Request) -> Result<Value> {
    let (id, bindings, tags) = (request.id, request.bindings, request.tags);
    let name = request.selected("host")?;
    let (file, text, found) = hosts()?;
    let Some(host) = found.iter().find(|host| host.name == name) else {
        bail!("{} keeps no {name}; nothing was changed", file.display());
    };
    let mut distinct: Vec<&str> = host
        .tokens
        .iter()
        .map(|(_, token)| token.as_str())
        .collect();
    distinct.sort_unstable();
    distinct.dedup();
    let token = match distinct.as_slice() {
        [] => bail!("{} keeps no token for {name} — gh may keep it in the system keyring; nothing was changed", file.display()),
        [token] => token.to_string(),
        _ => bail!("{} keeps {} different tokens for {name}, one per account; sign out of all but one with gh auth logout, then import", file.display(), distinct.len()),
    };
    let variable = variable(name);
    let binding = format!("{id}:{FIELD}");
    let updated = crate::runtime::npmcred::bound(bindings, &[(variable, &binding)])?;

    let mut fields = Map::new();
    fields.insert(FIELD.to_string(), json!(token));
    let mut context = Map::new();
    context.insert(
        crate::core::items::DISPLAY_NAME.to_string(),
        json!(format!("GitHub CLI token for {name}")),
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
            "{id} does not read back {name}'s token; {} was left as it was",
            file.display()
        );
    }

    if let Some(out) = updated {
        crate::core::vault::atomic_write(bindings, out.as_bytes())
            .with_context(|| format!("{} still keeps {name}'s token and {id} holds a copy, but {} could not bind {variable}", file.display(), bindings.display()))?;
    }
    crate::runtime::bindings::remember(bindings)?;
    let drop: Vec<usize> = host.tokens.iter().map(|(index, _)| *index).collect();
    let mut out: Vec<&str> = text
        .lines()
        .enumerate()
        .filter(|(index, _)| !drop.contains(index))
        .map(|(_, line)| line)
        .collect();
    if text.ends_with('\n') {
        out.push("");
    }
    crate::core::vault::atomic_write(&file, out.join("\n").as_bytes()).with_context(|| {
        format!("{} still keeps {name}'s token; {id} holds a copy and {} binds {variable}, so remove its oauth_token lines there", file.display(), bindings.display())
    })?;
    Ok(json!({
        "ok": true,
        "item": id,
        "entry": name,
        "variables": [variable],
        "file": file,
        "bindings": bindings,
        "run_with": format!("skarbiec exec --env-from {} -- gh <command>", bindings.display()),
        "next": format!("gh reads {name}'s token from {variable} now; run it through skarbiec exec, or it is signed out"),
    }))
}
