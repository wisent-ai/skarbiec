// `helper import kube <id> --user <name> [--tags <tag,...>]`: move the
// credential a kubeconfig user keeps into the vault, and make the user read
// it from there. A bearer token becomes a token item; a client certificate
// and key kept inline (client-certificate-data, client-key-data, as kind, k3s
// and minikube write them) become a certificate item. The credential is read
// as kubectl reads the kubeconfig, stored as a new item and read back; setup
// then gives the user this vault's exec, and only after that is it taken out
// of the kubeconfig with `kubectl config unset`. When that last step is
// refused the user keeps it beside the exec — kubectl still connects — and
// the refusal names the command that removes it; the credential never
// travels in an argument either way.

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::{json, Map, Value};

/// What a user keeps inline: the kind of item it becomes, its fields, and
/// the kubeconfig keys to unset once the user runs this vault's exec.
fn kept(
    user: &str,
    entry: &Value,
) -> Result<(&'static str, Map<String, Value>, Vec<&'static str>)> {
    let inline = |key: &str| entry[key].as_str().filter(|value| !value.is_empty());
    if let Some(token) = inline("token") {
        let mut fields = Map::new();
        fields.insert("token".to_string(), json!(token));
        return Ok((super::KIND, fields, vec!["token"]));
    }
    if let (Some(certificate), Some(key)) =
        (inline("client-certificate-data"), inline("client-key-data"))
    {
        let decode = |what: &str, data: &str| -> Result<String> {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data)
                .with_context(|| format!("kubeconfig user {user}'s {what} is not base64"))?;
            String::from_utf8(bytes)
                .with_context(|| format!("kubeconfig user {user}'s {what} is not PEM text"))
        };
        let mut fields = Map::new();
        fields.insert(
            "certificate".to_string(),
            json!(decode("client-certificate-data", certificate)?),
        );
        fields.insert(
            "private_key".to_string(),
            json!(decode("client-key-data", key)?),
        );
        return Ok((
            super::CERTIFICATE,
            fields,
            vec!["client-certificate-data", "client-key-data"],
        ));
    }
    if inline("client-certificate").is_some() || inline("client-key").is_some() {
        bail!("kubeconfig user {user} keeps its client certificate in files it names, not inline; `kubectl config set-credentials {user} --embed-certs --client-certificate=<file> --client-key=<file>` embeds them so they can be imported");
    }
    bail!("kubeconfig user {user} keeps neither a bearer token nor an inline client certificate to import; a user signing in with another plugin stays as it is")
}

pub(super) fn import(id: &str, user: &str, tags: Option<&String>) -> Result<Value> {
    let view: Value = serde_json::from_str(&super::kubectl(&[
        "view".to_string(),
        "--raw".to_string(),
        "-o".to_string(),
        "json".to_string(),
    ])?)
    .context("kubectl config view answered something that is not JSON")?;
    let entry = view["users"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| entry["name"] == json!(user))
        .with_context(|| {
            format!("the kubeconfig has no user {user}; `kubectl config view` lists its users")
        })?;
    let (kind, fields, keys) = kept(user, &entry["user"])?;

    let mut context = Map::new();
    context.insert(
        crate::core::items::DISPLAY_NAME.to_string(),
        json!(format!("kubeconfig user {user}")),
    );
    let payload = crate::core::schema::payload(kind, fields.clone(), context)?;
    let mut write = std::collections::HashMap::from([("type".to_string(), kind.to_string())]);
    if let Some(tags) = tags {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "helper import kube")?;
    let stored = crate::core::vault::Vault::open(crate::core::vault_path())?.get_item(id)?;
    if fields
        .iter()
        .any(|(field, value)| &stored["fields"][field] != value)
    {
        bail!(
            "{id} does not read back user {user}'s credential; the kubeconfig was left as it was"
        );
    }

    let set = super::setup(id, user)?;
    let mut removed = Vec::new();
    for key in &keys {
        let said = super::kubectl(&["unset".to_string(), format!("users.{user}.{key}")]).with_context(|| {
            format!("{id} holds user {user}'s credential and the user runs this vault's plugin, but users.{user}.{key} is still in the kubeconfig; `kubectl config unset users.{user}.{key}` removes it")
        })?;
        removed.push(said);
    }
    crate::runtime::audit::append(
        "kube-credential-import",
        &json!({"item": id, "user": user, "kind": kind}),
    )?;
    Ok(
        json!({"ok": true, "item": id, "kind": kind, "user": user, "program": set["program"], "kubectl": removed.join("; ")}),
    )
}
