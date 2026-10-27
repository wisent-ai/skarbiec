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

/// Every form of `totp`; `uri` and `missing` are answered by the
/// authenticator and logins modules, which this one leaves to them.
const USAGE: &str = "usage: totp code <item-id> | totp set <item-id> (the seed or otpauth:// address on stdin) | totp uri <item-id> | totp seed [<item-id>] | totp missing";

pub fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "totp" {
        return Ok(None);
    }
    let Some((verb, positionals)) = positionals.split_first() else {
        return Err(crate::cli::args::Usage(USAGE.to_string()).into());
    };
    match verb.as_str() {
        "set" => super::set_seed::run(positionals).map(Some),
        "code" => {
            let id = positionals.first().or_usage(USAGE)?;
            let vault = load()?;
            let resolved = resolve(&vault, vault.get_item(id)?)?;
            // A clock that cannot be read refuses the command with its cause;
            // it is never reported as a seed that made no code.
            let now = crate::core::clock::epoch_seconds()?;
            let inspected = inspect_seed(&resolved.payload, now);
            let state = inspected.state;
            let repair_for = repair_target(&resolved.identity, id);
            // How long the code stays current, so a reader types it before it
            // turns rather than after: the rest of this time step.
            let period = crate::core::totp::PERIOD_SECONDS;
            let seconds_left = period - now % period;
            Ok(Some(json!({
                "item": id,
                "identity": resolved.identity,
                "has_seed": state == SeedState::Present,
                "seed_state": state.as_str(),
                "description": state.description(),
                "code": inspected.code,
                "seconds_left": seconds_left,
                "reason": inspected.reason,
                "repair": state.repair().map(|repair| repair.replace("<login-item>", repair_for)),
            })))
        }
        // The seed-state diagnostic validates the stored value through the same
        // real TOTP computation as `totp code`, but never returns the short-lived
        // code or the seed itself.
        "seed" => {
            let vault = load()?;
            // One clock read for the sweep; a clock that cannot be read refuses
            // the command with its cause rather than marking every seed invalid.
            let now = crate::core::clock::epoch_seconds()?;
            // A row this vault cannot open, or one whose identity it cannot
            // open, is reported as unreadable with the cause, not silently
            // dropped and not guessed at: "no seed" and "the envelope is
            // unreadable" have nothing in common.
            let unreadable = |id: &str, kind: Option<Value>, error: anyhow::Error| {
                json!({
                    "item": id,
                    "kind": kind,
                    "seed_state": "unreadable",
                    "error": format!("{error:#}"),
                })
            };
            let row_for = |id: &str| match vault.get_item(id) {
                Ok(row) => {
                    let kind = row.get("kind").cloned();
                    let resolved = match resolve(&vault, row) {
                        Ok(resolved) => resolved,
                        Err(error) => return unreadable(id, kind, error),
                    };
                    // The same inspection as `totp`, without its code: the
                    // reason says why a Base32-shaped seed still made none.
                    let inspected = inspect_seed(&resolved.payload, now);
                    let state = inspected.state;
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
                        "reason": inspected.reason,
                        // The repair names the row that would carry the seed;
                        // a command an operator has to edit before running is
                        // a command they run wrong.
                        "repair": state.repair().map(|repair| repair.replace("<login-item>", repair_for)),
                    })
                }
                Err(error) => unreadable(id, None, error),
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
