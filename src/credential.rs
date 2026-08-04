use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::core::{crypto, inbox, schema, vault::Vault};
use crate::runtime::audit;

const WIRE_VERSION: &str = "skarbiec.credential-operation.v1";
const BRIDGE_ENV: &str = "SKARBIEC_WELES_CREDENTIAL_COMMAND";
const REQUEST_WRITER: &str = "skarbiec-credential-lifecycle";

const REQUEST_KIND: &str = "credential-operation";

struct CredentialOperationLock(PathBuf);

impl Drop for CredentialOperationLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn acquire_credential_operation_lock(vault_path: &Path) -> Result<CredentialOperationLock> {
    let lock_path = vault_path.with_extension("credential-operation.lock");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .with_context(|| {
            format!(
                "another credential operation owns {}; if its process crashed, verify no Weles task is active before removing the lock",
                lock_path.display()
            )
        })?;
    let guard = CredentialOperationLock(lock_path);
    writeln!(file, "{}", std::process::id())?;
    Ok(guard)
}

fn now_iso() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn exact_name(name: &str, value: &str, maximum: usize) -> Result<()> {
    let max = maximum;
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
    let max: usize = "200".parse()?;
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        bail!("purpose must be 1-200 printable UTF-8 bytes");
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
        "operation_plan",
        "operation_queued",
        "operation_completed",
        "needs_configuration",
        "needs_human_approval",
        "unsupported_operation",
        "operation_failed",
        "unsupported_secret",
    ]
    .contains(&status.as_str())
    {
        bail!("Weles returned unsupported credential-operation status");
    }
    Ok(json!({
        "status": status,
        "operation": safe_string(value, "operation"),
        "provider": safe_string(value, "provider"),
        "url": safe_string(value, "url"),
        "build_id": safe_string(value, "buildId"),
        "action_log_id": safe_string(value, "actionLogId"),
        "source_action_log_id": safe_string(value, "sourceActionLogId"),
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
    let response = sanitized_response(&parsed)?;
    let same_identity = response.get("operation").and_then(Value::as_str)
        == request.get("operation").and_then(Value::as_str)
        && response.get("provider").and_then(Value::as_str)
            == request.get("provider").and_then(Value::as_str)
        && response.get("vault_item_id").and_then(Value::as_str)
            == request.get("credential_id").and_then(Value::as_str);
    if !same_identity {
        bail!("Weles credential-operation response identity mismatch");
    }
    let response_status = response
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let action_log_id = response.get("action_log_id").and_then(Value::as_str);
    if response_status == "operation_queued" && action_log_id.is_none() {
        bail!("queued Weles credential operation is missing its action log id");
    }
    if request.get("mode").and_then(Value::as_str) == Some("status") {
        let requested_action_log_id = request.get("action_log_id").and_then(Value::as_str);
        let chained_from = response.get("source_action_log_id").and_then(Value::as_str);
        if action_log_id != requested_action_log_id && chained_from != requested_action_log_id {
            bail!("Weles credential-operation status task identity mismatch");
        }
    }
    Ok(response)
}

fn request_item_id(credential_id: &str) -> String {
    format!("operation:credential/{credential_id}")
}

fn request_payload(request: Value) -> Result<Value> {
    schema::field(&request, "value")
        .cloned()
        .context("credential operation record has no canonical value field")
}

fn request_envelope(request: &Value) -> Value {
    json!({
        "schema": schema::ITEM_SCHEMA,
        "kind": REQUEST_KIND,
        "fields": {"value": request},
        "context": {},
    })
}

fn live_item_exists(vault: &Vault, id: &str) -> bool {
    vault
        .list(false)
        .iter()
        .any(|entry| entry.get("id").and_then(Value::as_str) == Some(id))
}

fn save_request(vault_path: &Path, request_item: &str, request: &Value) -> Result<()> {
    Vault::open(vault_path.to_path_buf())?.set_managed_item(
        request_item,
        REQUEST_KIND,
        &request_envelope(request),
        &[],
        &[],
        crate::core::vault::ManagedWrite {
            controller: REQUEST_WRITER,
            writer: REQUEST_WRITER,
            operation_id: request.get("request_id").and_then(Value::as_str),
        },
    )
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
    save_request(vault_path, request_item, &updated)
}

fn item_revision(vault: &Vault, id: &str) -> Option<u64> {
    let item = vault.doc().get("items")?.get(id)?;
    if item.get("state").and_then(Value::as_str) == Some("trashed") {
        return None;
    }
    item.get("revision").and_then(Value::as_u64)
}

fn account_email(value: Option<&String>) -> Result<Option<String>> {
    let Some(value) = value.map(|value| value.trim().to_lowercase()) else {
        return Ok(None);
    };
    let valid = value.len() <= "254".parse()?
        && !value.chars().any(char::is_control)
        && value.split('@').count() == std::iter::once(()).count().saturating_add(1)
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
        });
    if !valid {
        bail!("--account must be one valid email address");
    }
    Ok(Some(value))
}

fn item_matches_request(
    vault: &Vault,
    credential_id: &str,
    request_id: &str,
    operation: &str,
    account_email: Option<&str>,
) -> bool {
    vault.get_item(credential_id).is_ok_and(|payload| {
        schema::field(&payload, "context")
            .ok()
            .and_then(Value::as_object)
            .is_some_and(|context| {
                context.get("request_id").and_then(Value::as_str) == Some(request_id)
                    && context.get("operation").and_then(Value::as_str) == Some(operation)
                    && account_email.is_none_or(|email| {
                        context.get("account_ref").and_then(Value::as_str) == Some(email)
                            && schema::field(&payload, "username")
                                .ok()
                                .and_then(Value::as_str)
                                == Some(email)
                    })
            })
    })
}

fn pending_matches_request(
    vault: &Vault,
    credential_id: &str,
    request_id: &str,
    field: &str,
    writer: &str,
) -> bool {
    vault
        .doc()
        .get("items")
        .and_then(|items| items.get(credential_id))
        .and_then(|item| item.get("pending"))
        .and_then(Value::as_object)
        .is_some_and(|pending| {
            pending.get("operation_id").and_then(Value::as_str) == Some(request_id)
                && pending.get("field").and_then(Value::as_str) == Some(field)
                && pending.get("written_by").and_then(Value::as_str) == Some(writer)
        })
}

pub(crate) fn authorize_managed_write(
    vault: &Vault,
    credential_id: &str,
    field: &str,
    writer: &str,
    operation_id: &str,
    allowed_operations: &[&str],
    expected_revision: u64,
) -> Result<()> {
    let request_item = request_item_id(credential_id);
    let request = vault
        .get_item(&request_item)
        .and_then(request_payload)
        .context("managed write has no active credential operation")?;
    let request_operation = request
        .get("operation")
        .and_then(Value::as_str)
        .context("credential operation has no operation")?;
    if !allowed_operations.contains(&request_operation)
        || request.get("request_id").and_then(Value::as_str) != Some(operation_id)
        || request.get("credential_id").and_then(Value::as_str) != Some(credential_id)
        || request.get("field").and_then(Value::as_str) != Some(field)
        || request.get("consumer").and_then(Value::as_str) != Some(writer)
        || request.get("baseline_revision").and_then(Value::as_u64) != Some(expected_revision)
        || !matches!(
            request.get("status").and_then(Value::as_str),
            Some("submitting" | "pending")
        )
    {
        bail!("managed write does not match the active credential operation");
    }
    if request_operation == "acquire" {
        if expected_revision != u64::MIN || live_item_exists(vault, credential_id) {
            bail!("credential acquisition requires an absent item at baseline revision zero");
        }
    } else if item_revision(vault, credential_id) != Some(expected_revision)
        || !inbox::managed_by_weles(vault, credential_id)
    {
        bail!("credential mutation baseline is no longer current and managed");
    }
    Ok(())
}

fn start_operation(
    operation: &str,
    vault_path: &Path,
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<Value> {
    let allowed = ["provider", "consumer", "purpose", "account", "dry-run"];
    let usage = format!(
        "usage: credential {operation} <item-id> --provider <provider> --consumer <consumer> [--account <email>] [--purpose <purpose>] [--dry-run]"
    );
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{usage}");
    }
    let credential_id = args.first().context(usage.clone())?;
    let provider = flags.get("provider").context("--provider is required")?;
    let consumer = flags.get("consumer").context("--consumer is required")?;
    exact_name("credential item id", credential_id, "200".parse()?)?;
    exact_name("provider", provider, "128".parse()?)?;
    exact_name("consumer", consumer, "200".parse()?)?;
    let purpose = purpose(flags.get("purpose"), consumer)?;
    let account = account_email(flags.get("account"))?;
    if provider == "microsoft" && account.is_none() {
        bail!("Microsoft credential operations require --account <email>");
    }
    let field = if provider == "microsoft" {
        "password"
    } else {
        "api_key"
    };
    let dry_run = flags.get("dry-run").is_some_and(|value| value == "true");
    let request_item = request_item_id(credential_id);
    let _request_lock = if dry_run {
        None
    } else {
        Some(acquire_credential_operation_lock(vault_path)?)
    };
    let mut resumable_request: Option<Value> = None;
    let baseline_revision = if dry_run {
        u64::MIN
    } else {
        let vault = Vault::open(vault_path.to_path_buf())?;
        let live = live_item_exists(&vault, credential_id);
        let managed = live && inbox::managed_by_weles(&vault, credential_id);
        match operation {
            "acquire" if managed => {
                return Ok(json!({
                    "ok": true,
                    "status": "managed",
                    "credential": credential_id,
                    "revision": item_revision(&vault, credential_id),
                }));
            }
            "acquire" if live => {
                bail!(
                    "{credential_id} already exists but has no Weles provenance; refusing to call it acquired"
                );
            }
            "rotate" | "verify" | "remove" if !managed => {
                bail!(
                    "{credential_id} is not an active Weles-managed credential; refusing external {operation}"
                );
            }
            _ => {}
        }
        if let Ok(existing) = vault.get_item(&request_item).and_then(request_payload) {
            if matches!(
                existing.get("status").and_then(Value::as_str),
                Some("submitting" | "pending" | "needs_human_approval")
            ) {
                let existing_operation = existing
                    .get("operation")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                if existing_operation != operation {
                    bail!(
                        "{credential_id} already has pending {existing_operation}; finish it before {operation}"
                    );
                }
                let identity_matches = existing.get("provider").and_then(Value::as_str)
                    == Some(provider.as_str())
                    && existing.get("consumer").and_then(Value::as_str) == Some(consumer.as_str())
                    && existing.get("purpose").and_then(Value::as_str) == Some(purpose.as_str())
                    && existing.get("account_email").and_then(Value::as_str) == account.as_deref();
                if !identity_matches {
                    bail!(
                        "{credential_id} has a conflicting pending {operation} request with different lifecycle identity"
                    );
                }
                let submitted = existing
                    .get("weles")
                    .and_then(|value| value.get("action_log_id"))
                    .and_then(Value::as_str)
                    .is_some();
                if submitted
                    || existing.get("status").and_then(Value::as_str)
                        == Some("needs_human_approval")
                {
                    return Ok(json!({
                        "ok": true,
                        "status": existing.get("status"),
                        "operation": operation,
                        "credential": credential_id,
                        "request_id": existing.get("request_id"),
                        "weles": existing.get("weles"),
                    }));
                }
                resumable_request = Some(existing);
            }
        }
        resumable_request
            .as_ref()
            .and_then(|request| request.get("baseline_revision"))
            .and_then(Value::as_u64)
            .unwrap_or_else(|| item_revision(&vault, credential_id).unwrap_or_default())
    };

    let request_id = match resumable_request
        .as_ref()
        .and_then(|request| request.get("request_id"))
        .and_then(Value::as_str)
    {
        Some(existing) => existing.to_string(),
        None => crypto::random_token()?,
    };
    let request = resumable_request.unwrap_or_else(|| {
        json!({
            "version": WIRE_VERSION,
            "mode": "submit",
            "action_log_id": Value::Null,
            "request_id": request_id,
            "operation": operation,
            "credential_id": credential_id,
            "provider": provider,
            "consumer": consumer,
            "account_email": account,
            "purpose": purpose,
            "baseline_revision": baseline_revision,
            "field": field,
            "status": "submitting",
            "created_at": now_iso(),
            "dry_run": dry_run,
        })
    });

    if !dry_run {
        save_request(vault_path, &request_item, &request)?;
        if let Err(error) = audit::append_sync(
            "credential-operation-request",
            &json!({
                "request_id": request_id,
                "operation": operation,
                "credential": credential_id,
                "provider": provider,
                "consumer": consumer,
            }),
        ) {
            update_request(vault_path, &request_item, &request, "failed", None)?;
            return Err(error);
        }
    }

    let mut submit_request = request.clone();
    submit_request
        .as_object_mut()
        .context("credential request is not an object")?
        .insert("status".to_string(), Value::String("pending".to_string()));
    let response = match run_weles(&submit_request) {
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
            "ok": response_status == "operation_plan",
            "operation": operation,
            "credential": credential_id,
            "request_id": request_id,
            "weles": response,
        }));
    }

    let accepted = matches!(response_status, "operation_queued" | "operation_completed");
    update_request(
        vault_path,
        &request_item,
        &request,
        if accepted { "pending" } else { response_status },
        Some(&response),
    )?;
    Ok(json!({
        "ok": accepted,
        "status": if accepted { "pending" } else { response_status },
        "operation": operation,
        "credential": credential_id,
        "request_id": request_id,
        "weles": response,
    }))
}

fn status(vault_path: &Path, args: &[String]) -> Result<Value> {
    let credential_id = args.first().context("usage: credential status <item-id>")?;
    exact_name("credential item id", credential_id, "200".parse()?)?;
    let request_item = request_item_id(credential_id);
    let mut vault = Vault::open(vault_path.to_path_buf())?;
    let mut request = match vault.get_item(&request_item).and_then(request_payload) {
        Ok(request) => request,
        Err(_) if inbox::managed_by_weles(&vault, credential_id) => {
            return Ok(json!({
                "ok": true,
                "status": "managed",
                "credential": credential_id,
                "revision": item_revision(&vault, credential_id),
                "externally_verified": false,
            }));
        }
        Err(_) if live_item_exists(&vault, credential_id) => {
            return Ok(json!({
                "ok": false,
                "status": "unmanaged",
                "credential": credential_id,
                "externally_verified": false,
            }));
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("no credential or operation request exists for {credential_id}")
            });
        }
    };
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .context("credential operation has no operation")?
        .to_string();
    let request_id = request
        .get("request_id")
        .and_then(Value::as_str)
        .context("credential operation has no request id")?
        .to_string();
    let field = request
        .get("field")
        .and_then(Value::as_str)
        .context("credential operation has no exact field")?
        .to_string();
    let writer = request
        .get("consumer")
        .and_then(Value::as_str)
        .context("credential operation has no exact writer")?
        .to_string();
    let account = (request.get("provider").and_then(Value::as_str) == Some("microsoft"))
        .then(|| request.get("account_email").and_then(Value::as_str))
        .flatten()
        .map(str::to_string);
    let mut current_status = request
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    if matches!(
        current_status.as_str(),
        "pending" | "operation_queued" | "needs_human_approval"
    ) {
        let action_log_id = request
            .get("weles")
            .and_then(|value| value.get("action_log_id"))
            .and_then(Value::as_str)
            .context("pending credential operation has no Weles action log id")?
            .to_string();
        let mut poll_request = request.clone();
        let object = poll_request
            .as_object_mut()
            .context("credential request is not an object")?;
        object.insert("mode".to_string(), Value::String("status".to_string()));
        object.insert("action_log_id".to_string(), Value::String(action_log_id));
        object.insert("status".to_string(), Value::String("pending".to_string()));
        object.remove("weles");
        object.remove("updated_at");
        let remote = run_weles(&poll_request)?;
        let remote_status = remote
            .get("status")
            .and_then(Value::as_str)
            .context("Weles status response is missing status")?;
        current_status = if remote_status == "operation_queued" {
            "pending".to_string()
        } else {
            remote_status.to_string()
        };
        update_request(
            vault_path,
            &request_item,
            &request,
            &current_status,
            Some(&remote),
        )?;
        vault = Vault::open(vault_path.to_path_buf())?;
        request = vault.get_item(&request_item).and_then(request_payload)?;
    }

    let mut confirmed = current_status == "completed";
    if current_status == "operation_completed" {
        confirmed = match operation.as_str() {
            "acquire" => {
                inbox::managed_by_weles(&vault, credential_id)
                    && inbox::written_by(&vault, credential_id).as_deref() == Some(writer.as_str())
                    && item_matches_request(
                        &vault,
                        credential_id,
                        &request_id,
                        &operation,
                        account.as_deref(),
                    )
            }
            "rotate" => {
                if !pending_matches_request(&vault, credential_id, &request_id, &field, &writer) {
                    false
                } else {
                    vault.activate_staged_revision(credential_id, &request_id, &field, &writer)?;
                    true
                }
            }
            "verify" => {
                let same = vault
                    .doc()
                    .get("items")
                    .and_then(|items| items.get(credential_id))
                    .and_then(|item| item.get("pending"))
                    .and_then(|pending| pending.get("same_as_current"))
                    .and_then(Value::as_bool)
                    == Some(true);
                if !same
                    || !pending_matches_request(&vault, credential_id, &request_id, &field, &writer)
                {
                    false
                } else {
                    vault.discard_staged_revision(credential_id, &request_id, &field, &writer)?;
                    true
                }
            }
            "remove" => {
                vault.trash_managed_item(credential_id, "weles", &writer)?;
                true
            }
            _ => false,
        };
        if confirmed {
            update_request(vault_path, &request_item, &request, "completed", None)?;
            audit::append_sync(
                "credential-operation-completed",
                &json!({
                    "credential": credential_id,
                    "operation": operation,
                    "request_id": request_id,
                    "field": field,
                }),
            )?;
            current_status = "completed".to_string();
            vault = Vault::open(vault_path.to_path_buf())?;
            request = vault.get_item(&request_item).and_then(request_payload)?;
        } else {
            update_request(vault_path, &request_item, &request, "inconsistent", None)?;
            current_status = "inconsistent".to_string();
        }
    } else if current_status == "operation_failed"
        && pending_matches_request(&vault, credential_id, &request_id, &field, &writer)
    {
        vault.discard_staged_revision(credential_id, &request_id, &field, &writer)?;
        audit::append_sync(
            "credential-operation-rollback",
            &json!({
                "credential": credential_id,
                "operation": operation,
                "request_id": request_id,
                "field": field,
            }),
        )?;
    }
    Ok(json!({
        "ok": confirmed,
        "status": current_status,
        "operation": operation,
        "credential": credential_id,
        "request_id": request.get("request_id"),
        "weles": request.get("weles"),
        "created_at": request.get("created_at"),
        "updated_at": request.get("updated_at"),
        "externally_verified": confirmed,
        "revision": item_revision(&vault, credential_id),
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
        operation @ ("acquire" | "rotate" | "verify" | "remove") => {
            start_operation(operation, vault_path, flags, args)?
        }
        "status" => status(vault_path, args)?,
        "help" => json!({
            "commands": [
                "credential acquire",
                "credential rotate",
                "credential verify",
                "credential remove",
                "credential status"
            ],
            "usage": "credential <acquire|rotate|verify|remove> <item-id> --provider <provider> --consumer <consumer> [--account <email>] [--purpose <purpose>] [--dry-run]",
        }),
        other => bail!("unknown credential command: {other}"),
    };
    Ok(Some(value))
}
