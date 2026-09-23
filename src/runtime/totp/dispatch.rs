use super::*;

pub fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "totp" => {
            let id = positionals.first().context("usage: totp <item-id>")?;
            let vault = load()?;
            let resolved = resolve(&vault, vault.get_item(id)?);
            let inspected = inspect_seed(&resolved.payload);
            let state = inspected.state;
            let repair_for = resolved.identity.clone().unwrap_or_else(|| id.to_string());
            Ok(Some(json!({
                "item": id,
                "identity": resolved.identity,
                "has_seed": state == SeedState::Present,
                "seed_state": state.as_str(),
                "description": state.description(),
                "code": inspected.code,
                "repair": state.repair().map(|repair| repair.replace("<login-item>", &repair_for)),
            })))
        }
        // The seed-state diagnostic validates the stored value through the same
        // real TOTP computation as `totp`, but never returns the short-lived
        // code or the seed itself.
        "totp-seed-state" => {
            let vault = load()?;
            // One item, or every row that can carry a factor in one vault
            // open: logins and the identities they sign in as. The sweep form
            // exists because the caller is a fleet diagnostic; asking per row
            // over a host channel would open the vault once per account.
            let ids: Vec<String> = match positionals.first() {
                Some(id) => vec![id.clone()],
                None => vault
                    .list(false)
                    .iter()
                    .filter(|row| {
                        matches!(
                            row.get("kind").and_then(Value::as_str),
                            Some("login") | Some("identity")
                        )
                    })
                    .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_string))
                    .collect(),
            };
            let rows: Vec<Value> = ids
                .iter()
                .map(|id| match vault.get_item(id) {
                    Ok(row) => {
                        let kind = row.get("kind").cloned().unwrap_or(Value::Null);
                        let resolved = resolve(&vault, row);
                        let state = seed_state(&resolved.payload);
                        let repair_for =
                            resolved.identity.clone().unwrap_or_else(|| id.to_string());
                        json!({
                            "item": id,
                            "kind": kind,
                            // Which row the factor was judged from: this one,
                            // or the identity this one signs in as. Without it
                            // a sweep reports the same seed once per platform
                            // row and an operator counts one account many
                            // times.
                            "identity": resolved.identity,
                            "seed_state": state.as_str(),
                            "description": state.description(),
                            // The repair names the row that would carry the
                            // seed; a command an operator has to edit before
                            // running is a command they run wrong.
                            "repair": state.repair().map(|repair| repair.replace("<login-item>", &repair_for)),
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
                })
                .collect();
            if !positionals.is_empty() {
                return Ok(Some(rows.into_iter().next().unwrap_or(Value::Null)));
            }
            Ok(Some(json!({"rows": rows})))
        }
        // The seed-state read a diagnostic can call. Deliberately separate
        // from `totp`: `totp` computes and returns a live one-time code, and a
        // fleet-wide sweep that only wants to know whether a seed exists must
        // not mint codes into a control plane's output to find out.
        "totp-seed-state" => {
            let vault = load()?;
            // One item, or every login row in one vault open. The sweep form
            // exists because the caller is a fleet diagnostic: asking per row
            // over a host channel would open the vault once per account.
            let ids: Vec<String> = match positionals.first() {
                Some(id) => vec![id.clone()],
                None => vault
                    .list(false)
                    .iter()
                    .filter(|row| row.get("kind").and_then(Value::as_str) == Some("login"))
                    .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_string))
                    .collect(),
            };
            let rows: Vec<Value> = ids
                .iter()
                .map(|id| match vault.get_item(id) {
                    Ok(row) => {
                        let state = seed_state(&row);
                        json!({
                            "item": id,
                            "kind": row.get("kind").cloned().unwrap_or(Value::Null),
                            "seed_state": state.as_str(),
                            "repair": state.repair(),
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
                })
                .collect();
            if positionals.first().is_some() {
                return Ok(Some(rows.into_iter().next().unwrap_or(Value::Null)));
            }
            Ok(Some(json!({"rows": rows})))
        }
        _ => Ok(None),
    }
}
