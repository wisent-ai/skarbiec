// `ci set kubernetes <namespace>/<name> --env-from <file> [--context
// <name>] [--yes]`: one Kubernetes Secret holding every value the bindings
// name, each under its variable name, so a Deployment's envFrom reads what
// the vault keeps. The manifest goes to `kubectl apply --server-side` on its
// standard input: server-side apply writes no last-applied annotation, which
// would otherwise keep every value again in plain text on the object.

use anyhow::Result;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::process::Command;

use crate::cli::args::{flag_set, Usage};
use crate::runtime::exec::Binding;

/// The field manager server-side apply records as owning the Secret's data.
const MANAGER: &str = "skarbiec";

pub(super) fn run(
    place: &str,
    flags: &HashMap<String, String>,
    bindings: &[Binding],
) -> Result<Value> {
    let Some((namespace, name)) = place
        .split_once('/')
        .filter(|(namespace, name)| super::named(namespace) && super::named(name))
    else {
        return Err(Usage(format!(
            "{place} is not <namespace>/<name> of a Kubernetes Secret; {}",
            super::USAGE
        ))
        .into());
    };
    let context = flags.get("context");
    if let Some(context) = context.filter(|context| context.is_empty()) {
        return Err(Usage(format!(
            "--context {context} names no kubectl context; {}",
            super::USAGE
        ))
        .into());
    }
    let listed = super::listed(bindings);
    if !flag_set(flags, "yes") {
        return Ok(
            json!({"ok": true, "applied": false, "secret": place, "context": context, "secrets": listed}),
        );
    }
    let mut data = Map::new();
    for (binding, value) in super::values(bindings)? {
        data.insert(binding.name.clone(), json!(value));
    }
    let manifest = json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {"name": name, "namespace": namespace},
        "stringData": data,
    });
    let mut command = Command::new("kubectl");
    if let Some(context) = context {
        command.args(["--context", context.as_str()]);
    }
    command.args([
        "apply",
        "--server-side",
        "--force-conflicts",
        "--field-manager",
        MANAGER,
        "-f",
        "-",
    ]);
    let output = super::piped(command, manifest.to_string().as_bytes(), "kubectl", place)?;
    let applied = output.status.success();
    let answer = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let refusal = String::from_utf8_lossy(&output.stderr).trim().to_string();
    crate::runtime::audit::append(
        "ci-secrets-kubernetes",
        &json!({"secret": place, "context": context, "secrets": listed, "applied": applied}),
    )?;
    if !applied {
        anyhow::bail!(
            "kubectl apply refused the Secret {place} ({}): {refusal}",
            output.status
        );
    }
    Ok(
        json!({"ok": true, "applied": true, "secret": place, "context": context, "secrets": listed, "kubectl": answer}),
    )
}
