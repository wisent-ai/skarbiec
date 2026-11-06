// `skarbiec ci set github <owner/repo> | kubernetes <namespace>/<name>
// --env-from <file> [...] [--yes]`: put the values a project's bindings file
// names where its CI or cluster reads them, so they read the same
// credentials the vault keeps and a rotation reaches them by running this
// again. The target's own CLI receives each value on its standard input —
// never an argument a process list shows, a file or this command's output.
// Without --yes it names what it would set.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Output, Stdio};

use crate::cli::args::{flag_set, OrUsage, Usage};
use crate::core::{vault::Vault, vault_path};
use crate::runtime::exec::Binding;

mod kept;
mod kubernetes;
mod rename;

pub(crate) use kept::list as kept_list;
pub use kept::pass as kept_pass;
pub(crate) use rename::follow_rename;

const USAGE: &str = "usage: ci set|keep github <owner/repo> --env-from <file> [--environment <name>] [--yes] | ci set|keep kubernetes <namespace>/<name> --env-from <file> [--context <name>] [--yes] | ci kept | ci forget <target> <place>";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "ci" {
        return Ok(None);
    }
    let answer = match positionals {
        [verb] if verb == "kept" => kept::list(),
        [verb, target, place] if verb == "keep" => kept::keep(target, place, flags),
        [verb, target, place] if verb == "forget" => kept::forget(target, place),
        [verb, target, place] if verb == "set" => push(target, place, flags),
        _ => Err(Usage(USAGE.to_string()).into()),
    };
    answer.map(Some)
}

/// Set the secrets the bindings name on one target, or with no yes name
/// what would be set.
fn push(target: &str, place: &str, flags: &HashMap<String, String>) -> Result<Value> {
    let bindings = crate::runtime::exec::bindings_in(flags.get("env-from").or_usage(USAGE)?)?;
    match target {
        "github" => github(place, flags, &bindings),
        "kubernetes" => kubernetes::run(place, flags, &bindings),
        other => Err(Usage(format!(
            "ci sets GitHub Actions or Kubernetes secrets; {other} is neither. {USAGE}"
        ))
        .into()),
    }
}

/// A name GitHub or Kubernetes takes as one path component.
fn named(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Each secret with the item field it comes from, never the value.
fn listed(bindings: &[Binding]) -> Vec<Value> {
    bindings
        .iter()
        .map(
            |binding| json!({"secret": binding.name, "item": binding.item, "field": binding.field}),
        )
        .collect()
}

/// Every value, read before the first is set, so a missing item or field
/// sets none of them.
fn values(bindings: &[Binding]) -> Result<Vec<(&Binding, String)>> {
    let vault = Vault::open(vault_path())?;
    let mut values = Vec::new();
    for binding in bindings {
        let payload = vault.get_item(&binding.item)?;
        let fields = crate::core::schema::fields(&payload)?;
        let Some(value) = fields.get(&binding.field).and_then(Value::as_str) else {
            bail!(
                "{} has no text field {} for {}; no secret was set",
                binding.item,
                binding.field,
                binding.name
            );
        };
        values.push((binding, value.to_string()));
    }
    Ok(values)
}

/// Run a target's CLI with `input` on its standard input and wait for it.
fn piped(mut command: Command, input: &[u8], program: &str, target: &str) -> Result<Output> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("start {program}, which sets the secrets on {target}"))?;
    child
        .stdin
        .take()
        .with_context(|| format!("{program} was started without a standard input"))?
        .write_all(input)
        .with_context(|| format!("hand the secret to {program}"))?;
    stado_wait::blocking(
        stado_wait::Kind::Process,
        "a CLI setting secrets",
        target,
        || child.wait_with_output(),
    )
    .with_context(|| format!("wait for {program}"))
}

fn github(repo: &str, flags: &HashMap<String, String>, bindings: &[Binding]) -> Result<Value> {
    let well_formed = repo
        .split_once('/')
        .is_some_and(|(owner, name)| named(owner) && named(name));
    if !well_formed {
        return Err(Usage(format!(
            "{repo} is not owner/repo as GitHub names a repository; {USAGE}"
        ))
        .into());
    }
    let environment = flags.get("environment");
    if let Some(environment) = environment.filter(|environment| environment.is_empty()) {
        return Err(Usage(format!(
            "--environment {environment} names no environment; {USAGE}"
        ))
        .into());
    }
    let listed = listed(bindings);
    if !flag_set(flags, "yes") {
        return Ok(
            json!({"ok": true, "applied": false, "repo": repo, "environment": environment, "secrets": listed}),
        );
    }
    let mut set = Vec::new();
    let mut refused = Vec::new();
    for (binding, value) in values(bindings)? {
        let mut command = Command::new("gh");
        command.args(["secret", "set", binding.name.as_str(), "--repo", repo]);
        if let Some(environment) = environment {
            command.args(["--env", environment.as_str()]);
        }
        match piped(command, value.as_bytes(), "gh", repo) {
            Ok(output) if output.status.success() => set.push(binding.name.clone()),
            Ok(output) => refused.push(json!({
                "secret": binding.name,
                "error": format!("gh secret set failed ({}): {}", output.status, String::from_utf8_lossy(&output.stderr).trim()),
            })),
            Err(error) => refused.push(json!({"secret": binding.name, "error": format!("{error:#}")})),
        }
    }
    crate::runtime::audit::append(
        "ci-secrets-set",
        &json!({"repo": repo, "environment": environment, "secrets": listed, "set": set, "refused": refused.len()}),
    )?;
    Ok(json!({
        "ok": refused.is_empty(),
        "applied": true,
        "repo": repo,
        "environment": environment,
        "secrets": listed,
        "set": set,
        "refused": refused,
    }))
}
