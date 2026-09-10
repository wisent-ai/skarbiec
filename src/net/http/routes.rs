// The route table: one request in, one handler chosen, one answer out.
// Mutating routes take the process-wide write lock; read-only routes do not.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::net::TcpStream;
use wisent_errors::Code;

use super::readiness::readiness_check;
use super::request::{credential_status_item, is_mutation, read_line_bounded};
use super::{
    bounded_detail, load, presented_identity, request_field, request_id, request_json,
    write_response, MAX_BODY_BYTES, MAX_HEADER_BYTES, MAX_REQUEST_LINE_BYTES, WRITE_LOCK,
};
use crate::access::grant;
use crate::credential::CREDENTIAL_OPERATIONS_PATH;
use crate::net::operator;

pub(super) fn handle(mut stream: TcpStream) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let Some(request_line) = read_line_bounded(&mut reader, MAX_REQUEST_LINE_BYTES)? else {
        return Ok(());
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let _write_guard = is_mutation(&method, &path).then(|| {
        WRITE_LOCK
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    });

    let mut headers: HashMap<String, String> = HashMap::new();
    let mut header_bytes = 0usize;
    loop {
        let remaining = MAX_HEADER_BYTES.saturating_sub(header_bytes);
        if remaining == 0 {
            return write_response(
                &mut stream,
                "HTTP/1.1 431 Request Header Fields Too Large",
                &json!({"error": "request headers too large"}),
            );
        }
        let Some(line) = read_line_bounded(&mut reader, remaining)? else {
            anyhow::bail!("request ended before headers");
        };
        header_bytes = header_bytes.saturating_add(line.len());
        if line.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    let body_len = match headers.get("content-length") {
        Some(value) => value.parse::<usize>().context("invalid content-length")?,
        None => 0,
    };
    if body_len > MAX_BODY_BYTES {
        return write_response(
            &mut stream,
            "HTTP/1.1 413 Content Too Large",
            &json!({"error": "request body too large"}),
        );
    }
    let mut body_buf = vec![Default::default(); body_len];
    reader.read_exact(&mut body_buf)?;
    let body = String::from_utf8_lossy(&body_buf).into_owned();

    let ok_line = "HTTP/1.1 200 OK";
    let bad_line = "HTTP/1.1 400 Bad Request";
    let unauthorized_line = "HTTP/1.1 401 Unauthorized";
    let denied_line = "HTTP/1.1 403 Forbidden";
    let missing_line = "HTTP/1.1 404 Not Found";
    let unavailable_line = "HTTP/1.1 503 Service Unavailable";

    // Operator routes (net/operator.rs): the surface a local console drives,
    // claimed before the consumer table so `/v1/operator/` is reserved whole.
    if operator::handle(&mut stream, &method, &path, &body)? {
        return Ok(());
    }
    if method == "GET" && path == "/livez" {
        return write_response(
            &mut stream,
            ok_line,
            &json!({"ok": true, "service": "skarbiec"}),
        );
    }
    if method == "GET" && matches!(path.as_str(), "/health" | "/readyz") {
        let readiness = readiness_check();
        let (crypto_active, crypto_limit, gpg_active, gpg_limit) =
            crate::core::crypto::executor_status();
        match readiness {
            Err(error) => write_response(
                &mut stream,
                unavailable_line,
                &json!({
                    "ok": false,
                    "service": "skarbiec",
                    "error_code": Code::InfraDown.as_str(),
                    "detail": bounded_detail(&error.to_string()),
                    "crypto": {
                        "active": crypto_active,
                        "limit": crypto_limit,
                        "gpg_active": gpg_active,
                        "gpg_limit": gpg_limit,
                    },
                }),
            ),
            Ok(canaries) => write_response(
                &mut stream,
                ok_line,
                &json!({
                    "ok": true,
                    "service": "skarbiec",
                    "canaries": canaries,
                    "crypto": {
                        "active": crypto_active,
                        "limit": crypto_limit,
                        "gpg_active": gpg_active,
                        "gpg_limit": gpg_limit,
                    },
                }),
            ),
        }?;
        return Ok(());
    }
    // `GET /list` and `GET /audit` are the pre-`/v1` spellings of the item
    // index. They were documented as compatibility routes for existing callers
    // and were left ungated on that basis; a search of every product in this
    // workspace — brama, stado, weles, jeden, probierz, wisent-backend,
    // wisent-integrations, the Swift desktop client, the native host and the
    // installed helpers under `~/.stado` — found no caller of either. Every
    // client reaches the index through `POST /v1/items/list`. So the sentence
    // was the only thing holding them open, and they now answer through the
    // same grant and the same per-item filter that route applies: an unnamed
    // caller on the loopback port can no longer read the whole index.
    //
    // They stay reachable rather than being deleted so that a caller nobody
    // found still reads a diagnosis. A 403 naming the missing grant says what
    // to fix; a 404 is indistinguishable from a wrong port or a dead daemon.
    if method == "GET" && path == "/list" {
        return crate::net::mcp::handle_items_list(&mut stream, &headers);
    }
    // Named for audit but only ever a count of the index, so it answers the
    // count of what this caller is allowed to see. The audit journal itself is
    // `/v1/operator/audit`.
    if method == "GET" && path == "/audit" {
        let Some(visible) = crate::net::mcp::authorized_items(&headers)? else {
            return crate::net::mcp::refuse_without_grant(&mut stream);
        };
        return write_response(&mut stream, ok_line, &json!({"items": visible.len()}));
    }
    if method == "POST" && path == "/v1/acquisitions" {
        return crate::net::mcp::handle_acquisitions_issue(&mut stream, &headers, &body);
    }
    if method == "POST" && path == "/v1/acquisitions/read" {
        let parsed = request_json(&body);
        let (Some(item), Some(field)) = (request_id(&parsed), request_field(&parsed)) else {
            return write_response(
                &mut stream,
                bad_line,
                &json!({"error": "exact id and field required"}),
            );
        };
        let (consumer, acquisition_token) = presented_identity(&headers);
        let acquired = if consumer.is_empty() {
            None
        } else {
            crate::access::acquisition::consume(&consumer, &acquisition_token, item, field)
                .unwrap_or(None)
        };
        let Some(acquired) = acquired else {
            return write_response(
                &mut stream,
                unauthorized_line,
                &json!({"error": "unauthorized"}),
            );
        };
        crate::runtime::audit::append_sync(
            "http-acquisition-consumed",
            &json!({"consumer": consumer, "item": item, "field": field}),
        )?;
        // The bound field, plus the one thing the item declares about itself
        // that a caller needs in order to know which flow the credential
        // belongs to. The key is absent when the item declares no provider.
        let mut answer = json!({
            "consumer": consumer,
            "item": item,
            "field": field,
            "value": acquired.value,
        });
        if let Some(provider) = acquired.provider {
            answer["provider"] = json!(provider);
        }
        return write_response(&mut stream, ok_line, &answer);
    }
    if method == "POST" && path == "/v1/items/list" {
        return crate::net::mcp::handle_items_list(&mut stream, &headers);
    }
    if method == "POST" && path == "/v1/tokens/introspect" {
        return crate::net::handle_tokens_introspect(&mut stream, &headers, &body);
    }
    if method == "POST" && path == "/v1/items/read" {
        return crate::net::handle_items_read(&mut stream, &headers, &body);
    }
    if method == "PUT" && path == "/v1/items" {
        return crate::net::handle_items_put(&mut stream, &headers, &body);
    }
    if method == "DELETE" && path == "/v1/items" {
        let parsed = request_json(&body);
        let Some(id) = request_id(&parsed) else {
            return write_response(&mut stream, bad_line, &json!({"error": "id required"}));
        };
        let (consumer, bearer) = presented_identity(&headers);
        let mut vault = load()?;
        if crate::credential::lifecycle_owned_item(&vault, id) {
            return write_response(
                &mut stream,
                denied_line,
                &json!({"error": "credential lifecycle requests and sealed directory contracts cannot be changed through item APIs"}),
            );
        }
        if consumer.is_empty()
            || !grant::token_allows_action(&vault, &consumer, &bearer, "trash", id)?
        {
            return write_response(
                &mut stream,
                denied_line,
                &json!({"error": "consumer not authorized to delete item"}),
            );
        }
        let known = vault
            .doc()
            .get("items")
            .and_then(Value::as_object)
            .is_some_and(|items| items.contains_key(id));
        if !known {
            return write_response(
                &mut stream,
                missing_line,
                &json!({"error": "item not found"}),
            );
        }
        if vault.ensure_owner_controlled(id).is_err() {
            return write_response(
                &mut stream,
                denied_line,
                &json!({"error": "item must be removed through its controlling lifecycle"}),
            );
        }
        vault.delete_item(id)?;
        crate::runtime::audit::append_sync(
            "http-item-delete",
            &json!({"item": id, "consumer": consumer}),
        )?;
        return write_response(&mut stream, ok_line, &json!({"ok": true, "id": id}));
    }
    // Credential lifecycle: the canonical Skarbiec is the only remote hop, so
    // every operation and every status poll arrives here.
    if method == "POST" && path == CREDENTIAL_OPERATIONS_PATH {
        return crate::net::handle_credential_operations(&mut stream, &headers, &body);
    }
    if let Some(item) = credential_status_item(&method, &path) {
        return crate::net::handle_credential_operation_status(&mut stream, &headers, item);
    }
    if method == "POST" && path == "/v1/route/resolve" {
        return crate::access::route::values::handle_http_resolve(&mut stream, &headers, &body);
    }
    // Bond endpoints (docs/design/bond.md): replica pull channel + p2p donations.
    if method == "GET" && path == "/v1/vault" {
        return crate::net::bond::handle_vault_pull(&mut stream, &headers);
    }
    if method == "GET" && path == "/v1/owner-pubkey" {
        return crate::net::handle_owner_pubkey(&mut stream);
    }
    if method == "POST" && path == "/v1/donations" {
        return crate::net::handle_donation(&mut stream, &headers, &body);
    }
    if method == "POST" && path == "/v1/enroll" {
        return crate::net::bond::handle_enroll(&mut stream, &headers, &body);
    }
    write_response(&mut stream, missing_line, &json!({"error": "not found"}))
}
