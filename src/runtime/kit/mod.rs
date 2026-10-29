// `kit`: the page an owner prints and keeps apart from every machine, so the
// vault can be opened again after the laptop is gone. It names what a
// restore needs — where the vault lives and syncs, whose key opens it, which
// recovery key stands behind that — and the steps, and holds no secret:
// the recovery secret key itself is kept offline, as `init` told the owner.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{vault::Vault, vault_path};

pub fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    _positionals: &[String],
) -> Result<Option<Value>> {
    if command != "kit" {
        return Ok(None);
    }
    kit().map(Some)
}

/// What a vault states, or null where it records nothing, so a missing piece
/// reads as missing on the printed page instead of as an empty line.
fn stated(text: &str) -> Value {
    if text.is_empty() {
        return Value::Null;
    }
    json!(text)
}

pub fn kit() -> Result<Value> {
    let path = vault_path();
    let vault = Vault::open(path.clone())?;
    let owner = vault.owner_uid().to_string();
    let owner_key = vault.recipient_fpr(&owner);
    let recovery_key = vault.recovery_fpr().to_string();
    // Where the vault is kept besides this file: each bond names its source
    // or replica, which is where a restore pulls from.
    let bonds = crate::bonds::dispatch("bond list", &HashMap::new(), &[])?;
    // The newest copy `backup` made, from the journal: where to look first
    // when this file is gone.
    let backups = crate::runtime::dispatch(
        "audit list",
        &HashMap::from([("op".to_string(), "vault-backed-up".to_string())]),
        &[],
    )?;
    let latest_backup = backups
        .as_ref()
        .and_then(|listed| listed.get("entries"))
        .and_then(Value::as_array)
        .and_then(|entries| entries.last())
        .map(|entry| json!({"at": entry.get("at"), "backup": entry.get("extra").and_then(|extra| extra.get("backup"))}));
    let missing: Vec<&str> = [
        (owner.is_empty(), "the vault records no owner"),
        (
            owner_key.is_none(),
            "the owner's key fingerprint is not registered",
        ),
        (
            recovery_key.is_empty(),
            "the vault records no recovery key, so losing the owner's key loses the vault",
        ),
    ]
    .into_iter()
    .filter_map(|(absent, why)| absent.then_some(why))
    .collect();
    let steps = [
        "Install Skarbiec on the new machine.",
        "Import the recovery secret key you kept offline: gpg --import <recovery-key file>.",
        "Bring the vault back: copy the latest backup below to the vault file's path (skarbiec backup check <copy> --open says it opens), or pull it from one of the bonds below.",
        "Run skarbiec doctor, then skarbiec recipient list, and replace the lost owner key with skarbiec owner rotate.",
    ];
    // The page as it is printed, so every surface prints the same one: the
    // desktop shows and prints it, and `kit | jq -r .page | lpr` prints it
    // from a shell.
    let mut page = vec![
        "Skarbiec emergency kit".to_string(),
        format!("Vault file: {}", path.display()),
        recorded("Owner", Some(owner.as_str())),
        recorded("Owner key fingerprint", owner_key.as_deref()),
        recorded("Recovery key fingerprint", Some(recovery_key.as_str())),
        recorded(
            "Latest backup",
            latest_backup
                .as_ref()
                .and_then(|entry| entry.get("backup"))
                .and_then(Value::as_str),
        ),
        recorded(
            "Latest backup made at",
            latest_backup
                .as_ref()
                .and_then(|entry| entry.get("at"))
                .and_then(Value::as_str),
        ),
    ];
    page.extend(missing.iter().map(|gap| format!("Missing: {gap}")));
    page.push("To restore, in this order:".to_string());
    page.extend(steps.iter().map(|step| format!("- {step}")));
    Ok(json!({
        "ok": missing.is_empty(),
        "vault_path": path,
        "owner": stated(&owner),
        "owner_key_fingerprint": owner_key,
        "recovery_key_fingerprint": stated(&recovery_key),
        "bonds": bonds,
        "latest_backup": latest_backup,
        "missing": missing,
        "steps": steps,
        "page": page.join("\n"),
        "holds_no_secret": true,
    }))
}

/// One line of the page: the piece the vault records, or that it records
/// none, so a gap reads as a gap on paper.
fn recorded(label: &str, value: Option<&str>) -> String {
    match value.filter(|text| !text.is_empty()) {
        Some(text) => format!("{label}: {text}"),
        None => format!("{label}: not recorded"),
    }
}
