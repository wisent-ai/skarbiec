// Talking to Weles: the admission route this host's Stado resolver hands
// Skarbiec for weles-admission, the bearer Skarbiec presents there, the
// request that is sent, and the answer that is believed back. All of it in
// process: no bridge program is started.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use super::super::common::{
    checked_bool, checked_code, checked_enum, checked_host, checked_uuid, safe_string,
};
use super::super::receipt::{
    checked_approval, checked_receipt, receipt_matches, DIRECTORY_IDENTITY_KEYS,
};
use super::super::{PROVIDER_EFFECTS, RESPONSE_PHASES, RESPONSE_STATUSES, ROLLBACK_STATUSES};
use super::{
    ADMISSION_CONSUMER, ADMISSION_PATH, ADMISSION_SERVICE, TOKEN_ENV, TOKEN_FILE_ENV, WIRE_VERSION,
};
use crate::core::effective_uid;

/// The bearer Skarbiec presents to Weles as its credential-operation caller:
/// `WELES_TOKEN`, else the owner-only file `WELES_TOKEN_FILE` names, else
/// `~/.stado/skarbiec-weles-credential-client-token`.
fn admission_bearer() -> Result<String> {
    if let Some(bearer) = crate::core::env::text(TOKEN_ENV)? {
        return Ok(bearer.trim().to_string());
    }
    let (path, source) = match crate::core::env::path(TOKEN_FILE_ENV) {
        Some(path) => (path, TOKEN_FILE_ENV),
        None => (
            crate::core::home_dir()
                .join(".stado")
                .join(format!("{ADMISSION_CONSUMER}-token")),
            "the default bearer file",
        ),
    };
    let remedy = format!(
        "issue the {ADMISSION_CONSUMER} grant and write its bearer to {} (owner-only), or name \
         another file with {TOKEN_FILE_ENV}",
        path.display()
    );
    let metadata = fs::symlink_metadata(&path).with_context(|| {
        format!(
            "WELES_CREDENTIAL_BEARER_UNRESOLVED: {source} {} cannot be read; {remedy}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & crate::core::mode::GROUP_AND_OTHER != 0
    {
        bail!(
            "WELES_CREDENTIAL_BEARER_UNRESOLVED: {source} {} must be a regular file this user \
             owns that no other account can read (chmod 600 it); {remedy}",
            path.display()
        );
    }
    let text = fs::read_to_string(&path).with_context(|| {
        format!(
            "WELES_CREDENTIAL_BEARER_UNRESOLVED: read {source} {}; {remedy}",
            path.display()
        )
    })?;
    let bearer = text.trim();
    if bearer.is_empty() || bearer.chars().any(char::is_whitespace) {
        bail!(
            "WELES_CREDENTIAL_BEARER_UNRESOLVED: {source} {} must hold exactly one bearer; {remedy}",
            path.display()
        );
    }
    Ok(bearer.to_string())
}

/// Where this host reaches Weles's credential-operation admission.
fn admission_route() -> Result<std::net::SocketAddr> {
    let url = crate::net::stado_route::route(ADMISSION_SERVICE, ADMISSION_CONSUMER).context(
        "WELES_ENDPOINT_UNRESOLVED: Stado answered no route to Weles credential admission",
    )?;
    crate::net::loopback::loopback_authority(&url).with_context(|| {
        format!(
            "WELES_ENDPOINT_UNRESOLVED: the route Stado answered for {ADMISSION_SERVICE}, {url}"
        )
    })
}

pub(in crate::credential) fn sanitized_response(value: &Value) -> Result<Value> {
    // A peer that names a version is naming the protocol it speaks: a
    // different one is a different contract, never a response we may read.
    if let Some(version) = value.get("version").filter(|version| !version.is_null()) {
        if version.as_str() != Some(WIRE_VERSION) {
            bail!("Weles response names an unsupported wire version; expected {WIRE_VERSION}");
        }
    }
    let status = safe_string(value, "status").context("Weles response missing status")?;
    if !RESPONSE_STATUSES.contains(&status.as_str()) {
        bail!("Weles returned unsupported credential-operation status");
    }
    let approval = checked_approval(value)?;
    if status == "needs_human_approval" && approval.is_none() {
        bail!("Weles asked for human approval without an approval resource to resume");
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
        "code": checked_code(value)?,
        "phase": checked_enum(value, "phase", RESPONSE_PHASES)?,
        "retryable": checked_bool(value, "retryable")?,
        "provider_effect": checked_enum(value, "providerEffect", PROVIDER_EFFECTS)?,
        "rollback_status": checked_enum(value, "rollbackStatus", ROLLBACK_STATUSES)?,
        "execution_host": checked_host(value)?,
        "tenant_id": checked_uuid(value, "tenantId")?,
        "principal_object_id": checked_uuid(value, "principalObjectId")?,
        "approval": approval,
        "receipt": checked_receipt(value)?,
    }))
}

/// Text Weles wrote that reaches an error message: control characters become
/// spaces and runs of whitespace one, so a multi-line answer reads as one
/// line. Nothing is cut.
pub(in crate::credential) fn sanitized_diagnostics(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

/// The answer for a request that never reached a Weles decision: the code and
/// why, with `needs_configuration` when nothing at the provider can have
/// changed and `operation_failed` with an unknown effect when it may have.
fn admission_failure(request: &Value, code: &str, message: &str, effect_unknown: bool) -> Value {
    let (status, effect) = if effect_unknown {
        ("operation_failed", "unknown")
    } else {
        ("needs_configuration", "none")
    };
    json!({
        "status": status,
        "operation": request.get("operation"),
        "provider": request.get("provider"),
        "vaultItemId": request.get("credential_id"),
        "actionLogId": request.get("action_log_id"),
        "code": code,
        "phase": "admission",
        "retryable": false,
        "providerEffect": effect,
        "message": sanitized_diagnostics(message.as_bytes()),
    })
}

/// Whether the request's provider, directory and field agree: an Entra
/// password carries its directory, every other provider none.
fn directory_agrees(request: &Value) -> bool {
    let directory = request.get("directory").filter(|value| !value.is_null());
    match request.get("provider").and_then(Value::as_str) {
        Some("microsoft_entra") => {
            request.get("field").and_then(Value::as_str) == Some("password")
                && directory.is_some_and(|directory| {
                    directory.get("provider").and_then(Value::as_str) == Some("microsoft_entra")
                })
        }
        _ => directory.is_none(),
    }
}

/// Send one credential operation to Weles's admission and read its answer,
/// or the admission failure naming why no answer came.
fn admit(request: &Value) -> Result<Value> {
    if !directory_agrees(request) {
        return Ok(admission_failure(
            request,
            "ENTRA_IDENTITY_CONTRACT_MISMATCH",
            &format!(
                "Directory identity and password field must agree with provider {} for {}",
                request["provider"], request["credential_id"]
            ),
            false,
        ));
    }
    let address = match admission_route() {
        Ok(address) => address,
        Err(error) => {
            return Ok(admission_failure(
                request,
                "WELES_ENDPOINT_UNRESOLVED",
                &format!("{error:#}"),
                false,
            ))
        }
    };
    let bearer = match admission_bearer() {
        Ok(bearer) => bearer,
        Err(error) => {
            return Ok(admission_failure(
                request,
                "WELES_CREDENTIAL_BEARER_UNRESOLVED",
                &format!("{error:#}"),
                false,
            ))
        }
    };
    let mut body = serde_json::to_vec(request)?;
    let authorization = format!("Bearer {bearer}");
    let sent = crate::net::loopback::exchange(
        address,
        "POST",
        ADMISSION_PATH,
        &[
            ("Authorization", authorization.as_str()),
            ("Content-Type", "application/json"),
            ("Accept", "application/json"),
        ],
        Some(&body),
        "Weles credential admission",
    );
    body.fill(b'\0');
    let mut reply = match sent {
        Ok(reply) => reply,
        // Sent and unanswered: whether Weles began the operation is unknown.
        Err(error) => {
            return Ok(admission_failure(
                request,
                "WELES_CREDENTIAL_TRANSPORT_FAILED",
                &format!("Weles credential admission did not return a bound response: {error:#}"),
                true,
            ))
        }
    };
    let parsed = serde_json::from_slice::<Value>(&reply.body);
    reply.body.fill(b'\0');
    let payload = match parsed {
        Ok(payload) => payload,
        Err(error) => {
            return Ok(admission_failure(
                request,
                "WELES_CREDENTIAL_TRANSPORT_FAILED",
                &format!(
                    "Weles credential admission answered {} with a body that is not JSON: {error}",
                    reply.status
                ),
                true,
            ))
        }
    };
    if (200..300).contains(&reply.code)
        || payload
            .get("status")
            .is_some_and(|status| !status.is_null())
    {
        return Ok(payload);
    }
    // A refusal without an operation state: its own code and message, or
    // its whole answer when it names no message.
    let code = match payload.get("code").and_then(Value::as_str) {
        Some(code) if !code.is_empty() => code.to_string(),
        _ => "WELES_CREDENTIAL_ADMISSION_REFUSED".to_string(),
    };
    let detail = match payload.get("message").and_then(Value::as_str) {
        Some(message) if !message.is_empty() => message.to_string(),
        _ => format!("the answer named no message: {payload}"),
    };
    let effect_unknown = payload.get("providerEffect").and_then(Value::as_str) != Some("none");
    Ok(admission_failure(
        request,
        &code,
        &format!(
            "Weles credential admission returned {}; {detail}",
            reply.status
        ),
        effect_unknown,
    ))
}

pub(in crate::credential) fn run_weles(request: &Value) -> Result<Value> {
    let parsed = admit(request)?;
    let dry_run = request.get("dry_run").and_then(Value::as_bool) == Some(true);
    match parsed.get("status").and_then(Value::as_str) {
        Some("operation_queued" | "operation_completed") if dry_run => {
            bail!("Weles executed a credential operation submitted as a dry run")
        }
        Some("operation_plan") if !dry_run => {
            bail!("Weles returned a plan for an executable credential operation")
        }
        _ => {}
    }
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
    // The sealed directory block is the only identity the response may echo.
    let directory = request.get("directory").filter(|value| !value.is_null());
    if let Some(directory) = directory {
        for key in DIRECTORY_IDENTITY_KEYS
            .iter()
            .copied()
            .filter(|key| *key != "account_upn")
        {
            let returned = response.get(key).and_then(Value::as_str);
            if returned.is_some() && returned != directory.get(key).and_then(Value::as_str) {
                bail!("Weles credential-operation response {key} does not match the sealed directory contract");
            }
        }
    }
    if let Some(receipt) = response.get("receipt").filter(|value| !value.is_null()) {
        // The receipt is checked against this request's own operation and id;
        // a request without them cannot vouch for any receipt.
        let operation = request
            .get("operation")
            .and_then(Value::as_str)
            .context("the credential-operation request names no operation, so Weles's receipt cannot be checked against it")?;
        let request_id = request
            .get("request_id")
            .and_then(Value::as_str)
            .context("the credential-operation request carries no request_id, so Weles's receipt cannot be checked against it")?;
        if !receipt_matches(receipt, directory, operation, request_id) {
            bail!(
                "Weles credential-operation receipt names another principal, request, or operation"
            );
        }
    }
    let action_log_id = response.get("action_log_id").and_then(Value::as_str);
    if response.get("status").and_then(Value::as_str) == Some("operation_queued")
        && action_log_id.is_none()
    {
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
