// `POST /v1/items/revision`: which version of one item field a read would
// answer now, without the value.
//
// A consumer that verifies bearers against a vault field (Stado's object
// plane) keeps the value it read and asks, per request, only whether it is
// still current. Reading the value each time decrypts it and appends an
// audit line, which is what exhausted the vault under object traffic; holding
// it for a fixed time instead let a rotated value keep working for that long.
// This answer takes the same grant as reading the field and decrypts nothing:
// `{id, item, item_uid, revision, field}`, the same version fields
// `/v1/items/read` returns beside the value. The value is audited when it is
// read; asking for its version reveals no value and is not.

use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::net::TcpStream;

use super::read::{locate, Located};
use crate::net::http;

pub(crate) fn handle_items_revision(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let Some(Located { requested, item, item_uid, revision, field, .. }) = locate(stream, headers, body)? else {
        return Ok(());
    };
    http::write_response(
        stream,
        "HTTP/1.1 200 OK",
        &json!({
            "id": requested,
            "item": item,
            "item_uid": item_uid,
            "revision": revision,
            "field": field,
        }),
    )
}
