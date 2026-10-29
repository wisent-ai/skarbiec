// `skarbiec alert set <id> --field <field> | alert status | alert test |
// alert unset`: tell a person when an unattended pass fails. A scheduled
// `maintain` or `rotation run` that fails is otherwise seen only by whoever
// reads its log; with an alert set, the failure is posted to a chat webhook —
// Slack, Mattermost, Discord, Teams — whose address an item keeps, because a
// webhook address is itself a secret that lets anyone post to the channel.
// Which item and field is this host's choice, kept beside the vault file in
// `<vault file>.alert`, never in the vault document replicas receive. The
// address reaches curl only on its standard input, as curl configuration,
// never in an argument a process list shows; the message names what failed
// and never a value.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cli::args::{OrUsage, Usage};
use crate::core::{vault::Vault, vault_path};

const USAGE: &str =
    "usage: alert set <id> --field <field> | alert status | alert test | alert unset";
const SCHEME: &str = "https://";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "alert" {
        return Ok(None);
    }
    match positionals {
        [action, id] if action == "set" => set(id, flags.get("field").or_usage(USAGE)?).map(Some),
        [action] if action == "status" => status().map(Some),
        [action] if action == "test" => {
            match send("skarbiec alert test: alerts from this vault reach this channel")? {
                Some(sent) => Ok(Some(sent)),
                None => bail!(
                "no alert is set on this host; `skarbiec alert set <id> --field <field>` sets one"
            ),
            }
        }
        [action] if action == "unset" => unset().map(Some),
        _ => Err(Usage(USAGE.to_string()).into()),
    }
}

/// Where this host's alert is kept: beside the vault file.
fn marker(vault: &Path) -> PathBuf {
    let mut name = vault.as_os_str().to_owned();
    name.push(".alert");
    PathBuf::from(name)
}

/// The item and field this host posts alerts through, when one is set.
fn configured() -> Result<Option<(String, String)>> {
    let path = marker(&vault_path());
    let Some(text) = crate::core::read_present(&path, "the alert setting")? else {
        return Ok(None);
    };
    let kept: Value =
        serde_json::from_str(&text).with_context(|| format!("{} is not JSON", path.display()))?;
    let field = |name: &str| {
        kept[name]
            .as_str()
            .map(str::to_string)
            .with_context(|| format!("{} names no {name}", path.display()))
    };
    Ok(Some((field("item")?, field("field")?)))
}

/// The webhook address `id`'s `field` holds, refused unless it is https and
/// can be written as one curl configuration line.
fn address(id: &str, field: &str) -> Result<String> {
    let payload = Vault::open(vault_path())?.get_item(id)?;
    let url = crate::core::schema::field(&payload, field)?
        .as_str()
        .with_context(|| format!("{id}'s {field} is not text"))?
        .trim()
        .to_string();
    if !url.starts_with(SCHEME) {
        bail!("{id}'s {field} is not an https:// address, so no alert is posted through it");
    }
    if url
        .chars()
        .any(|c| c == '"' || c == '\\' || c.is_control() || c.is_whitespace())
    {
        bail!("{id}'s {field} holds a character no webhook address carries");
    }
    Ok(url)
}

fn set(id: &str, field: &str) -> Result<Value> {
    address(id, field)?;
    let path = marker(&vault_path());
    let text = serde_json::to_string(&json!({"item": id, "field": field}))?;
    crate::core::vault::atomic_write(&path, text.as_bytes())
        .with_context(|| format!("write the alert setting {}", path.display()))?;
    crate::runtime::audit::append("alert-set", &json!({"item": id, "field": field}))?;
    Ok(
        json!({"ok": true, "item": id, "field": field, "setting": path, "next": "skarbiec alert test posts a message to check it"}),
    )
}

fn status() -> Result<Value> {
    let path = marker(&vault_path());
    match configured()? {
        Some((item, field)) => {
            Ok(json!({"ok": true, "set": true, "item": item, "field": field, "setting": path}))
        }
        None => Ok(json!({"ok": true, "set": false, "setting": path})),
    }
}

/// What doctor checks: the item and field this host's alert names, when one
/// is set, and why its webhook address cannot be read when it cannot — an
/// alert that cannot post fails silently exactly when it is needed.
pub(crate) fn check() -> Result<Option<(String, Option<String>)>> {
    let Some((item, field)) = configured()? else {
        return Ok(None);
    };
    let problem = address(&item, &field)
        .err()
        .map(|error| format!("{error:#}"));
    Ok(Some((format!("{item} · {field}"), problem)))
}

/// Point this host's alert at an item's new id after a rename, so failed
/// passes keep being posted; answers whether it named the old id.
pub(crate) fn follow_rename(from: &str, to: &str) -> Result<bool> {
    let Some((item, field)) = configured()? else {
        return Ok(false);
    };
    if item != from {
        return Ok(false);
    }
    let path = marker(&vault_path());
    let text = serde_json::to_string(&json!({"item": to, "field": field}))?;
    crate::core::vault::atomic_write(&path, text.as_bytes())
        .with_context(|| format!("point the alert setting {} at {to}", path.display()))?;
    Ok(true)
}

fn unset() -> Result<Value> {
    let path = marker(&vault_path());
    let Some((item, field)) = configured()? else {
        bail!("no alert is set on this host; nothing was changed");
    };
    std::fs::remove_file(&path)
        .with_context(|| format!("remove the alert setting {}", path.display()))?;
    crate::runtime::audit::append("alert-unset", &json!({"item": item, "field": field}))?;
    Ok(json!({"ok": true, "item": item, "field": field}))
}

/// Post `text` to the webhook this host's alert names; None when no alert
/// is set. The message is sent as both `text` (Slack, Mattermost, Teams)
/// and `content` (Discord).
pub(crate) fn send(text: &str) -> Result<Option<Value>> {
    let Some((item, field)) = configured()? else {
        return Ok(None);
    };
    let url = address(&item, &field)?;
    let body = json!({"text": text, "content": text}).to_string();
    let mut child = Command::new("curl")
        .args([
            "-sS",
            "--fail-with-body",
            "-K",
            "-",
            "-H",
            "Content-Type: application/json",
            "--data",
            &body,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start curl, which posts the alert")?;
    child
        .stdin
        .take()
        .context("curl was started without a standard input")?
        .write_all(format!("url = \"{url}\"\n").as_bytes())
        .context("hand the webhook address to curl")?;
    let output = stado_wait::blocking(
        stado_wait::Kind::Process,
        "curl posting an alert",
        &item,
        || child.wait_with_output(),
    )
    .context("wait for curl")?;
    if !output.status.success() {
        bail!(
            "the webhook {item} keeps refused the alert ({}): {} {}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    crate::runtime::audit::append("alert-sent", &json!({"item": item}))?;
    Ok(Some(json!({"ok": true, "sent": true, "item": item})))
}
