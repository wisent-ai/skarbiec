use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::core::{crypto, vault::Vault};
use crate::runtime::audit;

const WIRE_VERSION: &str = "skarbiec.credential-request.v1";
const BRIDGE_ENV: &str = "SKARBIEC_WELES_ACQUIRE_COMMAND";

fn now_iso() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn exact_name(name: &str, value: &str) -> Result<()> {
    let max: usize = "200".parse()?;
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("{name} must contain only ASCII letters, digits, '.', '_', or '-'");
    }
    Ok(())
}

fn purpose(value: Option<&String>, consumer: &str) -> Result<String> {
    let value = value.map(String::as_str).unwrap_or(consumer);
    let max: usize = "512".parse()?;
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        bail!("purpose must be 1-512 printable characters");
    }
    Ok(value.to_string())
}

fn effective_uid() -> Result<u32> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("read effective uid")?;
    if !output.status.success() {
        bail!("could not determine effective uid");
    }
    String::from_utf8(output.stdout)?
        .trim()
        .parse()
        .context("parse effective uid")
}

fn checked_bridge() -> Result<PathBuf> {
    let configured =
        std::env::var(BRIDGE_ENV).with_context(|| format!("{BRIDGE_ENV} is not set"))?;
    let path = Path::new(configured.trim());
    if !path.is_absolute() {
        bail!("{BRIDGE_ENV} must be an absolute path");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {BRIDGE_ENV} executable {}", path.display()))?;
    let unsafe_bits = u32::from_str_radix("022", "8".parse()?)?;
    let owner_execute = u32::from_str_radix("100", "8".parse()?)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid()?
        || metadata.permissions().mode() & unsafe_bits != u32::MIN
        || metadata.permissions().mode() & owner_execute == u32::MIN
    {
        bail!("{BRIDGE_ENV} must be an owner-controlled executable regular file");
    }
    fs::canonicalize(path).with_context(|| format!("canonicalize {BRIDGE_ENV}"))
}

fn safe_string(value: &Value, key: &str) -> Option<String> {
    let max: usize = "512".parse().ok()?;
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| text.len() <= max && !text.chars().any(char::is_control))
        .map(str::to_string)
}

fn sanitized_response(value: &Value) -> Result<Value> {
    let status = safe_string(value, "status").context("Weles response missing status")?;
    if ![
        "acquisition_plan",
        "acquisition_queued",
        "followup_queued",
        "needs_configuration",
        "unsupported_secret",
    ]
    .contains(&status.as_str())
    {
        bail!("Weles returned unsupported acquisition status");
    }
    Ok(json!({
        "status": status,
        "provider": safe_string(value, "provider"),
        "url": safe_string(value, "url"),
        "build_id": safe_string(value, "buildId"),
        "action_log_id": safe_string(value, "actionLogId"),
        "flow_name": safe_string(value, "flowName"),
        "vault_item_id": safe_string(value, "vaultItemId"),
        "message": safe_string(value, "message"),
    }))
}

fn run_weles(request: &Value) -> Result<Value> {
    let executable = checked_bridge()?;
    let mut child = Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("start Weles credential acquisition bridge")?;
    child
        .stdin
        .take()
        .context("open Weles bridge stdin")?
        .write_all(&serde_json::to_vec(request)?)?;

    let max: u64 = "65536".parse()?;
    let extra: u64 = "1".parse()?;
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .context("open Weles bridge stdout")?
        .take(max.saturating_add(extra))
        .read_to_end(&mut output)?;
    if u64::try_from(output.len())? > max {
        let _ = child.kill();
        let _ = child.wait();
        bail!("Weles credential acquisition response exceeded size limit");
    }
    let status = child
        .wait()
        .context("wait for Weles credential acquisition bridge")?;
    if !status.success() {
        bail!("Weles credential acquisition bridge failed");
    }
    let parsed: Value = serde_json::from_slice(&output).context("Weles response is not JSON")?;
    output.fill(u8::MIN);
    sanitized_response(&parsed)
}

fn request_item_id(credential_id: &str) -> String {
    format!("request:credential/{credential_id}")
}

fn live_item_exists(vault: &Vault, id: &str) -> bool {
    vault
        .list(false)
        .iter()
        .any(|entry| entry.get("id").and_then(Value::as_str) == Some(id))
}

fn update_request(
    vault_path: &Path,
    request_item: &str,
    request: &Value,
    status: &str,
    weles: Option<&Value>,
) -> Result<()> {
    let mut updated = request.clone();
    let object = updated
        .as_object_mut()
        .context("credential request is not an object")?;
    object.insert("status".to_string(), Value::String(status.to_string()));
    object.insert("updated_at".to_string(), Value::String(now_iso()));
    if let Some(response) = weles {
        object.insert("weles".to_string(), response.clone());
    }
    Vault::open(vault_path.to_path_buf())?.set_item(
        request_item,
        "credential_request",
        &updated,
        &[],
        &["credential-request".to_string()],
    )
}

fn acquire(vault_path: &Path, flags: &HashMap<String, String>, args: &[String]) -> Result<Value> {
    let allowed = ["provider", "consumer", "purpose", "dry-run"];
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("usage: credential acquire <item-id> --provider <provider> --consumer <consumer> [--purpose <purpose>] [--dry-run]");
    }
    let credential_id = args.first().context(
        "usage: credential acquire <item-id> --provider <provider> --consumer <consumer> [--purpose <purpose>] [--dry-run]",
    )?;
    let provider = flags.get("provider").context("--provider is required")?;
    let consumer = flags.get("consumer").context("--consumer is required")?;
    exact_name("credential item id", credential_id)?;
    exact_name("provider", provider)?;
    exact_name("consumer", consumer)?;
    let purpose = purpose(flags.get("purpose"), consumer)?;
    let dry_run = flags.get("dry-run").is_some_and(|value| value == "true");

    if !dry_run {
        let vault = Vault::open(vault_path.to_path_buf())?;
        if live_item_exists(&vault, credential_id) {
            return Ok(json!({"ok": true, "status": "ready", "credential": credential_id}));
        }
        let request_item = request_item_id(credential_id);
        if let Ok(existing) = vault.get_item(&request_item) {
            if existing.get("status").and_then(Value::as_str) == Some("pending") {
                return Ok(json!({
                    "ok": true,
                    "status": "pending",
                    "credential": credential_id,
                    "request_id": existing.get("request_id"),
                    "weles": existing.get("weles"),
                }));
            }
        }
    }

    let request_id = crypto::random_token()?;
    let request = json!({
        "version": WIRE_VERSION,
        "request_id": request_id,
        "credential_id": credential_id,
        "provider": provider,
        "consumer": consumer,
        "purpose": purpose,
        "status": "pending",
        "created_at": now_iso(),
        "dry_run": dry_run,
    });
    let request_item = request_item_id(credential_id);

    if !dry_run {
        Vault::open(vault_path.to_path_buf())?.set_item(
            &request_item,
            "credential_request",
            &request,
            &[],
            &["credential-request".to_string(), provider.to_string()],
        )?;
        audit::append_sync(
            "credential-acquire-request",
            &json!({
                "request_id": request_id,
                "credential": credential_id,
                "provider": provider,
                "consumer": consumer,
            }),
        )?;
    }

    let response = match run_weles(&request) {
        Ok(response) => response,
        Err(error) if !dry_run => {
            update_request(vault_path, &request_item, &request, "failed", None)?;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let response_status = response
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("failed");

    if dry_run {
        return Ok(json!({
            "ok": response_status == "acquisition_plan",
            "credential": credential_id,
            "request_id": request_id,
            "weles": response,
        }));
    }

    let pending = matches!(response_status, "acquisition_queued" | "followup_queued");
    update_request(
        vault_path,
        &request_item,
        &request,
        if pending { "pending" } else { "failed" },
        Some(&response),
    )?;
    Ok(json!({
        "ok": pending,
        "status": if pending { "pending" } else { response_status },
        "credential": credential_id,
        "request_id": request_id,
        "weles": response,
    }))
}

fn status(vault_path: &Path, args: &[String]) -> Result<Value> {
    let credential_id = args.first().context("usage: credential status <item-id>")?;
    exact_name("credential item id", credential_id)?;
    let mut vault = Vault::open(vault_path.to_path_buf())?;
    let request_item = request_item_id(credential_id);
    if live_item_exists(&vault, credential_id) {
        if vault.get_item(&request_item).is_ok() {
            vault.delete_item(&request_item)?;
            audit::append_sync(
                "credential-acquire-ready",
                &json!({"credential": credential_id}),
            )?;
        }
        return Ok(json!({"ok": true, "status": "ready", "credential": credential_id}));
    }
    let request = vault.get_item(&request_item).with_context(|| {
        format!("no credential or acquisition request exists for {credential_id}")
    })?;
    Ok(json!({
        "ok": request.get("status").and_then(Value::as_str) == Some("pending"),
        "status": request.get("status"),
        "credential": credential_id,
        "request_id": request.get("request_id"),
        "weles": request.get("weles"),
        "created_at": request.get("created_at"),
        "updated_at": request.get("updated_at"),
    }))
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
    vault_path: &Path,
) -> Result<Option<Value>> {
    if command != "credential" {
        return Ok(None);
    }
    let subcommand = positionals.first().map(String::as_str).unwrap_or("help");
    let args = positionals
        .get(std::iter::once(()).count()..)
        .unwrap_or_default();
    let value = match subcommand {
        "acquire" => acquire(vault_path, flags, args)?,
        "status" => status(vault_path, args)?,
        "help" => json!({
            "commands": ["credential acquire", "credential status"],
            "usage": "credential acquire <item-id> --provider <provider> --consumer <consumer> [--purpose <purpose>] [--dry-run]",
        }),
        other => bail!("unknown credential command: {other}"),
    };
    Ok(Some(value))
}
