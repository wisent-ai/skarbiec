use super::*;
use crate::cli::args::OrUsage;

/// The row a repair command names: the identity the factor was judged from
/// when the row signs in as one, otherwise the row itself.
fn repair_target<'r>(identity: &'r Option<String>, id: &'r str) -> &'r str {
    match identity {
        Some(identity) => identity,
        None => id,
    }
}

pub fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "totp" => {
            let id = positionals.first().or_usage("usage: totp <item-id>")?;
            let vault = load()?;
            let resolved = resolve(&vault, vault.get_item(id)?);
            let inspected = inspect_seed(&resolved.payload);
            let state = inspected.state;
            let repair_for = repair_target(&resolved.identity, id);
            Ok(Some(json!({
                "item": id,
                "identity": resolved.identity,
                "has_seed": state == SeedState::Present,
                "seed_state": state.as_str(),
                "description": state.description(),
                "code": inspected.code,
                "repair": state.repair().map(|repair| repair.replace("<login-item>", repair_for)),
            })))
        }
        // The seed-state diagnostic validates the stored value through the same
        // real TOTP computation as `totp`, but never returns the short-lived
        // code or the seed itself.
        "totp-seed-state" => {
            let vault = load()?;
            let row_for = |id: &str| match vault.get_item(id) {
                Ok(row) => {
                    let kind = row.get("kind").cloned();
                    let resolved = resolve(&vault, row);
                    let state = seed_state(&resolved.payload);
                    let repair_for = repair_target(&resolved.identity, id);
                    json!({
                        "item": id,
                        "kind": kind,
                        // Which row the factor was judged from: this one, or
                        // the identity this one signs in as. Without it a
                        // sweep reports the same seed once per platform row
                        // and an operator counts one account many times.
                        "identity": resolved.identity,
                        "seed_state": state.as_str(),
                        "description": state.description(),
                        // The repair names the row that would carry the seed;
                        // a command an operator has to edit before running is
                        // a command they run wrong.
                        "repair": state.repair().map(|repair| repair.replace("<login-item>", repair_for)),
                    })
                }
                // A row this vault cannot open is reported as itself, not
                // silently dropped and not guessed at: "no seed" and "the
                // envelope is unreadable" have nothing in common.
                Err(error) => json!({
                    "item": id,
                    "kind": Value::Null,
                    "seed_state": "unreadable",
                    "error": error.to_string(),
                }),
            };
            if let Some(id) = positionals.first() {
                return Ok(Some(row_for(id)));
            }
            // Every row that can carry a factor, in one vault open: logins and
            // the identities they sign in as. The sweep exists because the
            // caller is a fleet diagnostic; asking per row over a host channel
            // would open the vault once per account.
            let rows: Vec<Value> = vault
                .list(false)
                .iter()
                .filter(|row| {
                    matches!(
                        row.get("kind").and_then(Value::as_str),
                        Some("login") | Some("identity")
                    )
                })
                .filter_map(|row| row.get("id").and_then(Value::as_str))
                .map(row_for)
                .collect();
            Ok(Some(json!({"rows": rows})))
        }
        _ => Ok(None),
    }
}
