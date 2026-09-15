// Registering this replica's public key with a source serve.
//
// The local owner's fingerprint has to exist already: enrolling a vault
// with no registered key would hand a source an identity nobody can
// verify later.

use super::*;

pub(crate) fn cmd_enroll(flags: &HashMap<String, String>) -> Result<Value> {
    let uid = flags.get("as").context(
        "usage: enroll --as <uid> --to <base-url> --token <t> [--items a,b,c] [--consumer name]",
    )?;
    let to = flags.get("to").context("--to required")?;
    let token = flags.get("token").context("--token required")?;
    let consumer = flags
        .get("consumer")
        .map(String::as_str)
        .unwrap_or("enroll");
    let items: Vec<String> = flags
        .get("items")
        .map(|value| value.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    let vault = Vault::open(vault_path())?;
    let owner = vault.owner_uid().to_string();
    let fingerprint = vault
        .recipient_fpr(&owner)
        .context("local owner has no registered fingerprint")?;
    let armored = crypto::export_public_key(&fingerprint)?;
    let (_status, response) = crate::net::bond::serve_request(
        to,
        "POST",
        "/v1/enroll",
        consumer,
        token,
        Some(&json!({"uid": uid, "armored": armored, "items": items})),
    )?;
    crate::runtime::audit::append("enroll", &json!({"to": to, "uid": uid, "items": items}))?;
    Ok(response)
}
