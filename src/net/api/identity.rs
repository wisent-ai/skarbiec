// What a caller may learn about a credential without holding it: whether a
// bearer is live, and the owner's public key a donor seals to.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpStream;

use crate::access::grant;
use crate::core::crypto;
use crate::net::http;

/// Answer what an inbound bearer is, for a gateway that has to decide whether
/// to serve the request holding it.
///
/// The caller proves its own identity and must carry `introspect` on `tokens`;
/// asking about someone else's credential is a capability, not a side effect of
/// being able to reach this port. The subject bearer travels in the body and is
/// never logged, and an unknown bearer answers exactly like an expired one.
pub(crate) fn handle_tokens_introspect(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let parsed = http::request_json(body);
    let Some(subject) = parsed.get("token").and_then(Value::as_str) else {
        return http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": "token required"}),
        );
    };
    let (consumer, bearer) = http::presented_identity(headers);
    let vault = http::load()?;
    if consumer.is_empty()
        || !grant::token_allows_action(&vault, &consumer, &bearer, "introspect", "tokens")?
    {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "consumer not authorized to introspect tokens"}),
        );
    }
    let answer = grant::introspect(&vault, subject)?;
    crate::runtime::audit::append(
        "http-token-introspected",
        &json!({
            "consumer": consumer,
            "subject": answer.get("consumer").cloned().unwrap_or(Value::Null),
            "active": answer.get("active").cloned().unwrap_or(Value::Null),
        }),
    )?;
    http::write_response(stream, "HTTP/1.1 200 OK", &answer)
}

// === bond serve endpoints: the p2p donation path (docs/design/bond.md) ===

/// `GET /v1/owner-pubkey` — the vault owner's armored public key. A donor
/// needs it to seal a donation to this vault; the public half is not secret,
/// so no grant is required.
pub(crate) fn handle_owner_pubkey(stream: &mut TcpStream) -> Result<()> {
    let vault = http::load()?;
    let owner = vault.owner_uid().to_string();
    let fingerprint = vault
        .recipient_fpr(&owner)
        .context("owner has no registered fingerprint")?;
    let armored = crypto::export_public_key(&fingerprint)?;
    http::write_response(
        stream,
        "HTTP/1.1 200 OK",
        &json!({"ok": true, "owner": owner, "fingerprint": fingerprint, "armored": armored}),
    )
}
