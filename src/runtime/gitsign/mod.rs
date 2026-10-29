// `skarbiec signing setup <id> [--repo <dir>]`, `signing status [--repo
// <dir>]` and `signing unset [--repo <dir>]`: sign git commits and tags with
// an SSH key the vault keeps. setup sets git's own settings — gpg.format ssh,
// user.signingkey to the key-pair item's public key as a literal key, and
// commit.gpgsign and tag.gpgsign true — in the user's global configuration,
// or one repository's with --repo, so git signs every commit through the
// ssh-agent holding the key, which `skarbiec ssh add <id>` loads. No private
// key is written anywhere. status names the key git signs with, the item that
// keeps it and whether the agent holds it; unset removes the settings when
// the key is one this vault keeps. With --github, setup first adds the key to
// the GitHub account's signing keys (`github`), so GitHub shows the commits
// as verified.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;

use crate::cli::args::Usage;
use crate::core::{vault::Vault, vault_path};

mod github;

const USAGE: &str = "usage: signing setup <id> [--repo <dir>] [--github] | signing status [--repo <dir>] | signing unset [--repo <dir>]";
/// The prefix git reads a literal SSH public key from in user.signingkey.
const LITERAL: &str = "key::";
const SIGNING_KEY: &str = "user.signingkey";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "signing" {
        return Ok(None);
    }
    let scope = match flags.get("repo") {
        Some(repo) => Scope::Repo(repo.clone()),
        None => Scope::Global,
    };
    match positionals {
        [action, id] if action == "setup" => {
            setup(id, &scope, crate::cli::args::flag_set(flags, "github")).map(Some)
        }
        [action] if action == "status" => status(&scope).map(Some),
        [action] if action == "unset" => unset(&scope).map(Some),
        _ => Err(Usage(USAGE.to_string()).into()),
    }
}

enum Scope {
    Global,
    Repo(String),
}

impl Scope {
    fn named(&self) -> String {
        match self {
            Scope::Global => "the global git configuration".to_string(),
            Scope::Repo(repo) => format!("{repo}'s git configuration"),
        }
    }
}

/// Run `git config` in `scope`, answering git's output and whether it
/// succeeded; git config fails without a word when a key is unset.
fn git_config(scope: &Scope, args: &[&str]) -> Result<(bool, String, String)> {
    let mut command = Command::new("git");
    match scope {
        Scope::Global => command.args(["config", "--global"]),
        Scope::Repo(repo) => command.args(["-C", repo, "config", "--local"]),
    };
    let output = stado_wait::output(command.args(args))
        .context("run git config, which keeps git's signing settings")?;
    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
    ))
}

fn set(scope: &Scope, key: &str, value: &str) -> Result<()> {
    let (ok, _, said) = git_config(scope, &[key, value])?;
    if !ok {
        bail!("git config {key} in {} was refused: {said}", scope.named());
    }
    Ok(())
}

/// The public key a key-pair item keeps, as one line.
fn public_key(id: &str) -> Result<String> {
    let payload = Vault::open(vault_path())?.get_item(id)?;
    if payload["kind"] != json!("key-pair") {
        bail!(
            "{id} is a {} item; signing signs with the SSH key a key-pair item keeps",
            payload["kind"]
        );
    }
    payload["fields"]["public_key"]
        .as_str()
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_string)
        .with_context(|| {
            format!("{id} keeps no public_key; rotate {id} --with ssh makes a pair that has one")
        })
}

/// The live key-pair item whose public key is `key`, if the vault keeps one.
fn item_keeping(key: &str) -> Result<Option<String>> {
    let vault = Vault::open(vault_path())?;
    for entry in vault.list(false) {
        let (Some(id), Some("key-pair")) = (entry["id"].as_str(), entry["kind"].as_str()) else {
            continue;
        };
        let payload = vault.get_item(id)?;
        if payload["fields"]["public_key"]
            .as_str()
            .and_then(bare)
            .as_deref()
            == Some(key)
        {
            return Ok(Some(id.to_string()));
        }
    }
    Ok(None)
}

/// Whether the ssh-agent this process would use holds `key`.
fn agent_holds(key: &str) -> Value {
    match stado_wait::output(Command::new("ssh-add").arg("-L")) {
        Ok(output) => json!(String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.trim().starts_with(key))),
        Err(error) => json!({"error": format!("ssh-add -L could not run: {error:#}")}),
    }
}

/// The type and key of a public key line, without its comment; None for a
/// line that is not an SSH public key.
fn bare(key: &str) -> Option<String> {
    let words: Vec<&str> = key.split_whitespace().collect();
    match words.as_slice() {
        [kind, body, ..] => Some(format!("{kind} {body}")),
        _ => None,
    }
}

/// After rotate --with ssh replaced `old` with `new`, point the global git signing
/// setting at the new key when it named the old one, so commits keep being
/// signed by a key the agent can hold. Answers whether it moved, or why the
/// setting could not be read or written; the rotation stands either way.
pub(crate) fn follow_rotation(old: &str, new: &str) -> Value {
    let (Some(old), Some(new)) = (bare(old), bare(new)) else {
        return json!({"moved": false, "error": "the rotated key pair holds no SSH public key line"});
    };
    let scope = Scope::Global;
    let configured = match git_config(&scope, &[SIGNING_KEY]) {
        Ok((true, value, _)) => value,
        Ok((false, _, _)) => return json!({"moved": false}),
        Err(error) => return json!({"moved": false, "error": format!("{error:#}")}),
    };
    if configured.strip_prefix(LITERAL).and_then(bare).as_deref() != Some(old.as_str()) {
        return json!({"moved": false});
    }
    match set(&scope, SIGNING_KEY, &format!("{LITERAL}{new}")) {
        Ok(()) => json!({"moved": true, "scope": scope.named()}),
        Err(error) => json!({"moved": false, "error": format!("{error:#}")}),
    }
}

fn setup(id: &str, scope: &Scope, on_github: bool) -> Result<Value> {
    let signing = bare(&public_key(id)?)
        .with_context(|| format!("{id}'s public_key is not an SSH public key line"))?;
    // GitHub first: when it refuses, git is left as it was.
    let github = match on_github {
        true => github::publish(id, &signing)
            .with_context(|| format!("{} was left as it was", scope.named()))?,
        false => Value::Null,
    };
    set(scope, "gpg.format", "ssh")?;
    set(scope, SIGNING_KEY, &format!("{LITERAL}{signing}"))?;
    set(scope, "commit.gpgsign", "true")?;
    set(scope, "tag.gpgsign", "true")?;
    crate::runtime::audit::append(
        "git-sign-setup",
        &json!({"item": id, "scope": scope.named(), "github": on_github}),
    )?;
    Ok(json!({
        "ok": true,
        "item": id,
        "scope": scope.named(),
        "public_key": signing,
        "github": github,
        "agent_holds_it": agent_holds(&signing),
        "load_it": format!("skarbiec ssh add {id}"),
    }))
}

fn status(scope: &Scope) -> Result<Value> {
    let (set, value, _) = git_config(scope, &[SIGNING_KEY])?;
    let Some(key) = value.strip_prefix(LITERAL).filter(|_| set) else {
        return Ok(
            json!({"ok": true, "scope": scope.named(), "signing_key": if set { json!(value) } else { Value::Null }, "item": Value::Null}),
        );
    };
    let Some(key) = bare(key) else {
        bail!(
            "{} signs with {value}, which is not an SSH public key",
            scope.named()
        );
    };
    Ok(
        json!({"ok": true, "scope": scope.named(), "signing_key": key, "item": item_keeping(&key)?, "agent_holds_it": agent_holds(&key)}),
    )
}

fn unset(scope: &Scope) -> Result<Value> {
    let (set, value, _) = git_config(scope, &[SIGNING_KEY])?;
    let Some(key) = value.strip_prefix(LITERAL).filter(|_| set) else {
        bail!(
            "{} signs with no key set by signing setup, so nothing was changed",
            scope.named()
        );
    };
    let kept = bare(key).with_context(|| {
        format!(
            "{} signs with {value}, which is not an SSH public key, so it is left alone",
            scope.named()
        )
    })?;
    let Some(item) = item_keeping(&kept)? else {
        bail!(
            "{} signs with a key no item here keeps, so it is left alone",
            scope.named()
        );
    };
    for key in [SIGNING_KEY, "gpg.format", "commit.gpgsign", "tag.gpgsign"] {
        let (ok, _, said) = git_config(scope, &["--unset", key])?;
        if !ok && !said.is_empty() {
            bail!(
                "git config --unset {key} in {} was refused: {said}",
                scope.named()
            );
        }
    }
    crate::runtime::audit::append(
        "git-sign-unset",
        &json!({"item": item, "scope": scope.named()}),
    )?;
    Ok(json!({"ok": true, "item": item, "scope": scope.named()}))
}
