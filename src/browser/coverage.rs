// What the browser host's grant reaches. It names exact items, minted by
// `browser install` for the logins that existed then, so a login added
// later — by login new, an import or set — is one the extension cannot
// list or fill until install runs again. Status says which.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{schema, vault::Vault, vault_path};

/// Whether `consumer` holds a grant in the vault, and the live logins it
/// does not reach.
pub(super) fn of(consumer: &str) -> Result<(bool, Vec<String>)> {
    let vault = Vault::open(vault_path())?;
    let Some(grant) = vault
        .doc()
        .get("tokens")
        .and_then(|tokens| tokens.get(consumer))
    else {
        return Ok((false, Vec::new()));
    };
    let reached: Vec<String> = grant
        .get("capabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|capability| {
            capability
                .get("item")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();
    let missing = vault
        .list(false)
        .iter()
        .filter(|row| row.get("kind").and_then(Value::as_str) == Some("login"))
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .filter(|id| !reached.iter().any(|reach| reach == id))
        .map(str::to_string)
        .collect();
    Ok((true, missing))
}

/// Widen the browser host's grant to one login just written here — its
/// context and the username, password and totp_secret it holds — with `grant
/// ensure`, proving possession with the token file `browser install`
/// wrote, so the extension offers it at once and its bearer stays as it is.
/// Where autofill is not connected on this machine there is nothing to
/// widen, and the answer says so instead of failing the write that called it.
pub fn cover_login(id: &str) -> Result<Value> {
    let token = super::HostPaths::of(&super::home_dir()?).token;
    if !super::present(&token)? {
        return Ok(
            json!({"covered": false, "reason": "browser autofill is not connected on this machine"}),
        );
    }
    let payload = Vault::open(vault_path())?.get_item(id)?;
    let mut fields = vec!["context"];
    for field in ["username", "password", "totp_secret"] {
        if schema::field(&payload, field).is_ok() {
            fields.push(field);
        }
    }
    let mut added = Vec::new();
    let mut refused = Vec::new();
    for field in fields {
        let flags = HashMap::from([
            ("field".to_string(), field.to_string()),
            ("token-file".to_string(), token.display().to_string()),
        ]);
        let positionals = [
            "ensure".to_string(),
            super::CONSUMER.to_string(),
            id.to_string(),
        ];
        match crate::access::dispatch("grant", &flags, &positionals) {
            Ok(_) => added.push(field),
            Err(error) => refused.push(json!({"field": field, "error": format!("{error:#}")})),
        }
    }
    Ok(json!({"covered": refused.is_empty(), "fields": added, "refused": refused}))
}

/// `browser cover`: widen the grant to every live login it does not
/// reach yet, as login new does for one, keeping the bearer the extension
/// holds; each login answers as cover_login answers it.
pub fn cover_all() -> Result<Value> {
    let (granted, missing) = of(super::CONSUMER)?;
    if !granted {
        anyhow::bail!("the browser host holds no grant here; run `skarbiec browser install` first");
    }
    let mut logins = serde_json::Map::new();
    for id in &missing {
        logins.insert(id.clone(), cover_login(id)?);
    }
    let covered = logins
        .values()
        .all(|answer| answer["covered"] == json!(true));
    Ok(json!({"ok": covered, "logins": logins}))
}

/// The autofill step of `maintain`: on a machine where the extension is
/// connected (a grant and the token file install wrote), cover every login
/// added since, so one imported or written elsewhere is offered without a
/// visit to Settings. Elsewhere, or on a replica whose grants its source
/// writes, it is skipped and says why.
pub fn maintain_pass() -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    if crate::cli::items::ensure_not_replica(&vault, "browser cover").is_err() {
        return Ok(json!({"skipped": "this vault is a replica; its source widens its grants"}));
    }
    drop(vault);
    let (granted, _) = of(super::CONSUMER)?;
    if !granted {
        return Ok(json!({"skipped": "browser autofill holds no grant in this vault"}));
    }
    if !super::present(&super::HostPaths::of(&super::home_dir()?).token)? {
        return Ok(json!({"skipped": "browser autofill is not connected on this machine"}));
    }
    cover_all()
}

/// What `doctor` reads about autofill on this machine: `None` where it is
/// not connected (no grant in the vault or no token file install wrote),
/// else the live logins the extension cannot offer yet.
pub fn reach() -> Result<Option<Vec<String>>> {
    let (granted, missing) = of(super::CONSUMER)?;
    if !granted || !super::present(&super::HostPaths::of(&super::home_dir()?).token)? {
        return Ok(None);
    }
    Ok(Some(missing))
}
