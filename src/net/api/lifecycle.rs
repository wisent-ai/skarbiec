// Credential lifecycle over the wire: submit, resume and status. One
// capability action, `lifecycle`, which authorizes no read of a value.

use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::net::TcpStream;

use crate::access::grant;
use crate::net::{detail_text, http};

// === credential lifecycle serve endpoints ===
//
// The canonical Skarbiec is the only remote hop of a credential lifecycle, so
// submit, resume, and status all arrive here. They accept exactly one
// capability action, `lifecycle`, which authorizes no read of a credential
// value: these handlers never call a read path.

/// The consumer holding one exact `lifecycle` capability on one exact item,
/// or `None` once the refusal is written: a request presenting no identity is
/// answered naming what it lacks, before the vault is read, and one without
/// the grant is answered naming the grant.
fn lifecycle_consumer(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    item: &str,
) -> Result<Option<String>> {
    let (consumer, bearer) = match http::presented_identity(headers) {
        Ok(identity) => identity,
        Err(reason) => {
            http::unidentified(stream, &reason)?;
            return Ok(None);
        }
    };
    let vault = http::load()?;
    let lifecycle = crate::access::actions::Action::Lifecycle.as_str();
    if !grant::token_allows_action(&vault, &consumer, &bearer, lifecycle, item)? {
        http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": format!("lifecycle:{item} grant required")}),
        )?;
        return Ok(None);
    }
    Ok(Some(consumer))
}

/// `POST /v1/credential/operations` — submit or resume one credential
/// operation. The body carries no directory identity: that is a sealed item
/// contract Skarbiec reads for itself.
pub(crate) fn handle_credential_operations(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let Some(parsed) = http::request_json(stream, body)? else {
        return Ok(());
    };
    let item = match crate::credential::endpoint_item(&parsed) {
        Ok(item) => item,
        Err(error) => {
            return http::write_response(
                stream,
                "HTTP/1.1 400 Bad Request",
                &json!({"error": detail_text(&format!("{error:#}"))}),
            );
        }
    };
    let Some(consumer) = lifecycle_consumer(stream, headers, &item)? else {
        return Ok(());
    };
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
            &json!({"ok": false, "error": detail_text(&format!("{error:#}"))}),
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
                &json!({"error": detail_text(&format!("{error:#}"))}),
            );
        }
    };
    if lifecycle_consumer(stream, headers, &item)?.is_none() {
        return Ok(());
    }
    match crate::credential::status_from_endpoint(&crate::core::vault_path(), &item) {
        Ok(value) => http::write_response(stream, "HTTP/1.1 200 OK", &value),
        Err(error) => http::write_response(
            stream,
            "HTTP/1.1 409 Conflict",
            &json!({"ok": false, "error": detail_text(&format!("{error:#}"))}),
        ),
    }
}
