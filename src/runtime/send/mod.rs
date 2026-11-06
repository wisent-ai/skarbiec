// `send <id> --field <field>`: hand one value to a person who has no place in
// the vault — a contractor, a relative, a support desk. The value is sealed
// with a fresh random passphrase into an armored OpenPGP message: the message
// goes one way (mail, chat), the passphrase another (a call, a text), and
// `gpg --decrypt` with the passphrase opens it anywhere. Nothing is stored;
// the journal records that the field was sent, never the value or the phrase.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::{OrUsage, Usage};
use crate::core::{crypto, schema, vault::Vault, vault_path};

const USAGE: &str = "usage: send <id> --field <field>";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "send" {
        return Ok(None);
    }
    let [id] = positionals else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let field = flags.get("field").or_usage(USAGE)?;
    seal(id, field).map(Some)
}

/// Seal one text field of one item; called by the command line and by
/// `POST /v1/operator/items/send`.
pub fn seal(id: &str, field: &str) -> Result<Value> {
    let payload = Vault::open(vault_path())?.get_item(id)?;
    let value = schema::field(&payload, field)?.as_str().with_context(|| {
        format!("{id}'s {field} is not text, so it cannot be sent as a message")
    })?;
    let passphrase = crypto::random_token()?;
    let message = crypto::seal_with_passphrase(&passphrase, value)?;
    crate::runtime::audit::append("item-sent", &json!({"item": id, "field": field}))?;
    Ok(json!({
        "ok": true,
        "item": id,
        "field": field,
        "message": message,
        "passphrase": passphrase,
        "open_with": "gpg --decrypt, then the passphrase",
    }))
}
