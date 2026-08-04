// One-time-code helper. For a canonical login item that stores a base32 seed,
// emit the CURRENT time-based code (via the standard oath toolkit) — like a
// password manager's built-in authenticator. The seed value itself is never
// emitted; only the short-lived code.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{crypto, schema, vault::Vault, vault_path};

fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

fn seed_of(payload: &Value) -> Option<String> {
    schema::field(payload, "totp_secret")
        .ok()
        .and_then(Value::as_str)
        .map(str::to_string)
}

pub fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "totp" => {
            let id = positionals.first().context("usage: totp <item-id>")?;
            let vault = load()?;
            let row = vault.get_item(id)?;
            match seed_of(&row) {
                Some(seed) => {
                    let code = crypto::totp_code(&seed);
                    let note = if code.is_none() {
                        json!("install oath-toolkit (oathtool) to compute codes")
                    } else {
                        Value::Null
                    };
                    Ok(Some(
                        json!({"item": id, "has_seed": true, "code": code, "note": note}),
                    ))
                }
                None => Ok(Some(json!({"item": id, "has_seed": false}))),
            }
        }
        _ => Ok(None),
    }
}
