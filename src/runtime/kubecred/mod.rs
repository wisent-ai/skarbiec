// The kube adapter of `skarbiec helper`: a kubectl exec credential plugin
// (https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins),
// so kubectl, helm and every client-go program read a cluster credential from
// the vault each time they connect, and none sits in ~/.kube/config: a token
// item's bearer token, or a certificate item's client certificate and private
// key, which kind, k3s and minikube clusters sign users in with. `helper
// answer kube <id>` prints the ExecCredential the protocol defines and
// journals the read. `helper setup kube <id> --user <name>` has kubectl itself
// make the kubeconfig user run it — kubectl config set-credentials, so
// KUBECONFIG and every other member of the file are kubectl's to keep —
// `helper import kube <id> --user <name>` moves the token a user keeps into a
// new item and does the same, `helper unset kube --user <name>` has kubectl
// remove that exec again, and status names the users that run it.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;

use crate::cli::args::Usage;
use crate::core::{vault::Vault, vault_path};

mod import;

pub(crate) const TOOL: &str = "kube";
pub(crate) const USAGE: &str = "usage: helper setup kube <id> --user <kubeconfig user> | helper import kube <id> --user <kubeconfig user> [--tags <tag,...>] | helper unset kube --user <kubeconfig user> | helper answer kube <id>  (kubectl's exec plugin)";
const KIND: &str = "token";
/// The kind holding a client certificate and its private key.
const CERTIFICATE: &str = "certificate";
/// The client authentication API this plugin answers in.
const API_VERSION: &str = "client.authentication.k8s.io/v1";

/// setup, import and unset, the verb first.
pub(crate) fn person(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let user = || {
        flags
            .get("user")
            .ok_or_else(|| Usage(format!("name the kubeconfig user with --user; {USAGE}")))
    };
    match positionals {
        [action, id] if action == "setup" => {
            credential(id)?;
            setup(id, user()?)
        }
        [action, id] if action == "import" => import::import(id, user()?, flags.get("tags")),
        [action] if action == "unset" => unset(user()?),
        _ => Err(Usage(USAGE.to_string()).into()),
    }
}

/// kubectl's side: the ExecCredential for the item its user names.
pub(crate) fn answer(_flags: &HashMap<String, String>, arguments: &[String]) -> Result<()> {
    let [id] = arguments else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let status = credential(id)?;
    crate::runtime::audit::append("kube-credential", &json!({"item": id}))?;
    crate::cli::args::emit(&json!({"apiVersion": API_VERSION, "kind": "ExecCredential", "status": status}))
}

/// The kubeconfig users that run this vault's plugin, each with the item it
/// reads and whether its program is still there; without kubectl no user can
/// run it, and that is said.
pub(crate) fn status() -> Result<Value> {
    if !kubectl_on_path()? {
        return Ok(json!({"kubectl": false, "users": []}));
    }
    let listed = users()?
        .iter()
        .map(|user| {
            let present = crate::core::is_present(&user.program, "the kubeconfig user's plugin program")?;
            Ok(json!({"user": user.name, "item": user.item, "program": user.program, "program_exists": present}))
        })
        .collect::<Result<Vec<Value>>>()?;
    Ok(json!({"kubectl": true, "users": listed}))
}

/// The ExecCredential status an item answers: a token item's token, or a
/// certificate item's certificate (with its chain) and private key, refusing
/// any other kind and an item missing what its kind needs.
fn credential(id: &str) -> Result<Value> {
    let payload = Vault::open(vault_path())?.get_item(id)?;
    let fields = &payload["fields"];
    let text = |field: &str| {
        fields[field]
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .with_context(|| format!("{id} holds no {field}"))
    };
    match payload["kind"].as_str() {
        Some(KIND) => Ok(json!({"token": text("token")?})),
        Some(CERTIFICATE) => {
            let mut certificate = text("certificate")?;
            if let Some(chain) = fields["chain"].as_str().filter(|chain| !chain.trim().is_empty()) {
                certificate = format!("{}\n{}", certificate.trim_end(), chain.trim());
            }
            Ok(json!({"clientCertificateData": certificate, "clientKeyData": text("private_key")?}))
        }
        _ => bail!(
            "{id} is a {} item; helper answer kube hands kubectl the token a {KIND} item keeps or the client certificate and key a {CERTIFICATE} item keeps",
            payload["kind"]
        ),
    }
}

/// Run `kubectl config <args>`, naming kubectl's own words when it refuses.
fn kubectl(args: &[String]) -> Result<String> {
    let output = stado_wait::output(Command::new("kubectl").arg("config").args(args))
        .context("run kubectl config, which keeps the kubeconfig")?;
    if !output.status.success() {
        bail!("kubectl config {} ({}): {}", args.join(" "), output.status, String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn setup(id: &str, user: &str) -> Result<Value> {
    let program = std::env::current_exe().context("name this skarbiec binary for the kubeconfig")?;
    let mut args = vec![
        "set-credentials".to_string(),
        user.to_string(),
        format!("--exec-api-version={API_VERSION}"),
        format!("--exec-command={}", program.display()),
    ];
    for word in crate::runtime::helper::invocation(TOOL).split_whitespace() {
        args.push(format!("--exec-arg={word}"));
    }
    args.push(format!("--exec-arg={id}"));
    args.push("--exec-interactive-mode=Never".to_string());
    let said = kubectl(&args)?;
    crate::runtime::audit::append("kube-credential-setup", &json!({"item": id, "user": user}))?;
    Ok(json!({"ok": true, "item": id, "user": user, "program": program, "kubectl": said}))
}

fn unset(user: &str) -> Result<Value> {
    let users = users()?;
    let Some(found) = users.iter().find(|found| found.name == user) else {
        bail!("no kubeconfig user {user} runs this vault's helper answer kube; `kubectl config view` shows the users there");
    };
    let said = kubectl(&["unset".to_string(), format!("users.{user}.exec")])?;
    crate::runtime::audit::append("kube-credential-unset", &json!({"user": user, "item": found.item}))?;
    Ok(json!({"ok": true, "user": user, "item": found.item, "kubectl": said}))
}

/// One kubeconfig user whose exec runs this vault's helper answer kube.
pub(crate) struct KubeUser {
    pub(crate) name: String,
    pub(crate) program: std::path::PathBuf,
    pub(crate) item: String,
}

/// Whether kubectl is on PATH: where it is not, no kubeconfig user can run
/// this vault's plugin, and doctor has nothing of kubectl's to check. A PATH
/// candidate that cannot be examined is the error naming it, not "absent".
pub(crate) fn kubectl_on_path() -> Result<bool> {
    match std::env::var_os("PATH") {
        Some(path) => Ok(crate::core::presence::on_path("kubectl", &path)?.is_some()),
        None => Ok(false),
    }
}

/// Point every kubeconfig user that runs this vault's plugin for `from` at
/// `to` after a rename, as setup would; each user moved or not is named.
/// Without kubectl no user can run the plugin, so there is none to move.
pub(crate) fn follow_rename(from: &str, to: &str) -> Result<Value> {
    if !kubectl_on_path()? {
        return Ok(json!({"moved": [], "not_moved": []}));
    }
    let mut moved = Vec::new();
    let mut not_moved = Vec::new();
    for user in users()?.iter().filter(|user| user.item == from) {
        match setup(to, &user.name) {
            Ok(_) => moved.push(user.name.clone()),
            Err(error) => not_moved.push(json!({"user": user.name, "error": format!("{error:#}")})),
        }
    }
    Ok(json!({"moved": moved, "not_moved": not_moved}))
}

/// Every kubeconfig user whose exec runs helper answer kube, as kubectl reads
/// the kubeconfig, so unset and doctor see what kubectl would run.
pub(crate) fn users() -> Result<Vec<KubeUser>> {
    let view: Value = serde_json::from_str(&kubectl(&["view".to_string(), "-o".to_string(), "json".to_string()])?)
        .context("kubectl config view answered something that is not JSON")?;
    let listed = view["users"].as_array().into_iter().flatten();
    Ok(listed
        .filter_map(|user| {
            let exec = &user["user"]["exec"];
            let args: Vec<&str> = exec["args"].as_array()?.iter().filter_map(Value::as_str).collect();
            let [item] = crate::runtime::helper::invoked(TOOL, &args)? else { return None };
            Some(KubeUser {
                name: user["name"].as_str()?.to_string(),
                program: std::path::PathBuf::from(exec["command"].as_str()?),
                item: (*item).to_string(),
            })
        })
        .collect())
}
