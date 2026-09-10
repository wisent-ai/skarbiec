// Credential lifecycle over the wire: submit, resume and status. One
// capability action, `lifecycle`, which authorizes no read of a value.

use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::net::TcpStream;

use crate::access::grant;
use crate::net::{bounded_detail, http};

// === credential lifecycle serve endpoints ===
//
// The canonical Skarbiec is the only remote hop of a credential lifecycle, so
// submit, resume, and status all arrive here. They accept exactly one
// capability action, `lifecycle`, which authorizes no read of a credential
// value: these handlers never call a read path.

/// One exact `lifecycle` capability on one exact item.
fn lifecycle_authorized(headers: &HashMap<String, String>, item: &str) -> Result<bool> {
    let (consumer, bearer) = http::presented_identity(headers);
    if consumer.is_empty() {
        return Ok(false);
    }
    let vault = http::load()?;
    grant::token_allows_action(&vault, &consumer, &bearer, "lifecycle", item)
}

/// `POST /v1/credential/operations` — submit or resume one credential
/// operation. The body carries no directory identity: that is a sealed item
/// contract Skarbiec reads for itself.
pub(crate) fn handle_credential_operations(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let parsed = http::request_json(body);
    let item = match crate::credential::endpoint_item(&parsed) {
        Ok(item) => item,
        Err(error) => {
            return http::write_response(
                stream,
                "HTTP/1.1 400 Bad Request",
                &json!({"error": bounded_detail(&error.to_string())}),
            );
        }
    };
    if !lifecycle_authorized(headers, &item)? {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": format!("lifecycle:{item} grant required")}),
        );
    }
    let (consumer, _) = http::presented_identity(headers);
    match crate::credential::submit_from_endpoint(&crate::core::vault_path(), &parsed) {
        Ok(value) => {
            crate::runtime::audit::append(
                "http-credential-operation",
                &json!({
                    "item": item,
                    "consumer": consumer,
                    "status": value.get("status"),
                    "operation": value.get("operation"),
                }),
            )?;
            http::write_response(stream, "HTTP/1.1 200 OK", &value)
        }
        Err(error) => http::write_response(
            stream,
            "HTTP/1.1 409 Conflict",
            &json!({"ok": false, "error": bounded_detail(&error.to_string())}),
        ),
    }
}

/// `GET /v1/credential/operations/<item>` — the persisted state of that item's
/// credential operation, with its receipt and quarantine block.
pub(crate) fn handle_credential_operation_status(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    item: &str,
) -> Result<()> {
    let item = match crate::credential::exact_credential_item(item) {
        Ok(item) => item,
        Err(error) => {
            return http::write_response(
                stream,
                "HTTP/1.1 400 Bad Request",
                &json!({"error": bounded_detail(&error.to_string())}),
            );
        }
    };
    if !lifecycle_authorized(headers, &item)? {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": format!("lifecycle:{item} grant required")}),
        );
    }
    match crate::credential::status_from_endpoint(&crate::core::vault_path(), &item) {
        Ok(value) => http::write_response(stream, "HTTP/1.1 200 OK", &value),
        Err(error) => http::write_response(
            stream,
            "HTTP/1.1 409 Conflict",
            &json!({"ok": false, "error": bounded_detail(&error.to_string())}),
        ),
    }
}
