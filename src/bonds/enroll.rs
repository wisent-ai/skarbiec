// Registering this replica's public key with a source serve.
//
// The local owner's fingerprint has to exist already: enrolling a vault
// with no registered key would hand a source an identity nobody can
// verify later.

use super::*;
use crate::cli::args::OrUsage;

/// The consumer an enrolment presents when `--consumer` names none, as the
/// command's published usage declares.
const DECLARED_CONSUMER: &str = "enroll";

pub(crate) fn cmd_enroll(flags: &HashMap<String, String>) -> Result<Value> {
    let uid = flags.get("as").or_usage(
        "usage: enroll --as <uid> --to <base-url> --token-file <path> [--items a,b,c] [--consumer name]",
    )?;
    let to = flags.get("to").or_usage("--to required")?;
    let token = &crate::credential::bearer_from_file(flags, "enroll")?;
    let consumer = match flags.get("consumer") {
        Some(named) => named.as_str(),
        None => DECLARED_CONSUMER,
    };
    // `--items` names the items to request; without it the enrolment
    // requests none and only registers the key.
    let items: Vec<String> = match flags.get("items") {
        Some(listed) => listed.split(',').map(str::to_string).collect(),
        None => Vec::new(),
    };
    let vault = Vault::open(vault_path())?;
    let owner = vault.owner_uid().to_string();
    let fingerprint = vault
        .recipient_fpr(&owner)
        .context("local owner has no registered fingerprint")?;
    let armored = crypto::export_public_key(&fingerprint)?;
    let (_status, response) = crate::net::serve::serve_request(
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
