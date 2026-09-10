// What the vault itself answers: which file was selected, whether it opens,
// and whether the journal beside it still links.

use serde_json::{json, Value};
use std::collections::HashMap;
use crate::core::vault_path;
use crate::runtime::{audit, vaults};

use super::{check, DIGEST_WINDOW, FAIL, NOT_CONFIGURED, PASS};

/// The vault, read as a file rather than asked over HTTP.
pub(super) fn vault_check() -> Value {
    let path = crate::core::vault_path();
    match crate::core::items::status_json() {
        Ok(status) => {
            let items = status.get("item_count").and_then(Value::as_u64);
            let tokens = status.get("token_count").and_then(Value::as_u64);
            match items {
                Some(count) => check(
                    "vault",
                    PASS,
                    format!(
                        "{count} items, {} grants, at {}",
                        tokens.unwrap_or_default(),
                        path.display()
                    ),
                ),
                None => check(
                    "vault",
                    FAIL,
                    format!("{} reported no item count", path.display()),
                ),
            }
        }
        Err(error) => check("vault", FAIL, format!("{}: {error}", path.display())),
    }
}


/// The hash chain, split the way `verify-chain` splits it.
pub(super) fn audit_check() -> Value {
    let mut flags = HashMap::new();
    flags.insert("tail".to_string(), DIGEST_WINDOW.to_string());
    match audit::chain_report(&flags) {
        Ok(report) => {
            let journal = report
                .get("journal")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let linked = report
                .get("linkage_verified")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            let total = report
                .get("linkage_checked")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            let digests = report
                .get("digests_verified")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            let intact = report
                .get("intact")
                .and_then(Value::as_bool)
                .unwrap_or_default();
            let faults = report
                .get("faults")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let detail = if intact {
                format!("{linked} of {total} entries linked, newest {digests} digests intact, in {journal}")
            } else {
                let first = faults
                    .first()
                    .map(|fault| {
                        format!(
                            "line {} ({})",
                            fault
                                .get("line")
                                .and_then(Value::as_u64)
                                .unwrap_or_default(),
                            fault.get("at").and_then(Value::as_str).unwrap_or_default()
                        )
                    })
                    .unwrap_or_else(|| "an unreported position".to_string());
                format!(
                    "{linked} of {total} entries linked, newest {digests} digests intact; {} fault(s), first at {first}, in {journal}",
                    faults.len()
                )
            };
            check("audit", if intact { PASS } else { FAIL }, detail)
        }
        Err(error) => check("audit", FAIL, error.to_string()),
    }
}

/// The file name a routes table takes beside the vault it serves.
const ROUTES_TABLE: &str = "capability-routes.json";

/// Which vault answered, out of how many, and on whose authority.
///
/// Every other check reports on the vault it was handed. This one reports the
/// handing over. `vault_path` resolves a request override first, then
/// `SKARBIEC_VAULT_FILE`, then falls back to `$HOME/.local/share/skarbiec`,
/// and the fallback is silent: a bare `skarbiec` on a host holding several
/// vaults picks the first search path and says nothing about the others. That
/// silence is how a vault written by an unpinned command becomes the default
/// answer for every command afterwards, indistinguishable at the surface from
/// the vault an operator believes they are running.
///
/// Two conditions are worth an operator's attention, and both are reported as
/// one because they have one remedy - name the vault explicitly:
///
/// - the vault was chosen by fallback while other vaults are visible, and
/// - a vault sits at the default path with no routes table beside it, which
///   is a broker that resolves every resource to nothing and only says so
///   when `route verify` is finally run against it.
///
/// Nothing is decrypted and no item name is reported; the counts come from
/// the same cleartext envelope `vaults` reads.
pub(super) fn selection_check() -> Value {
    let resolved = vault_path();
    let selected_by = if std::env::var_os("SKARBIEC_VAULT_FILE").is_some() {
        "SKARBIEC_VAULT_FILE"
    } else {
        "the HOME fallback"
    };
    let explicit = selected_by == "SKARBIEC_VAULT_FILE";

    let visible = vaults::inventory()
        .ok()
        .and_then(|report| report.get("vaults").cloned())
        .and_then(|found| found.as_array().cloned())
        .unwrap_or_default();
    let others: Vec<String> = visible
        .iter()
        .filter_map(|vault| vault.get("path").and_then(Value::as_str))
        .filter(|path| std::path::Path::new(path) != resolved)
        .map(str::to_string)
        .collect();

    // A default-path vault with no table beside it is worth naming even when
    // it is not the vault that answered, because it is the vault that answers
    // whenever the variable is dropped.
    let default = default_vault_path();
    let orphan_default = default.is_file() && !default.with_file_name(ROUTES_TABLE).is_file();

    if !resolved.is_file() {
        let mut entry = check(
            "selection",
            NOT_CONFIGURED,
            format!("no vault at {}, named by {selected_by}", resolved.display()),
        );
        entry["resolved"] = json!(resolved.display().to_string());
        entry["selected_by"] = json!(selected_by);
        entry["candidates"] = json!(visible);
        return entry;
    }

    let ambiguous = !explicit && !others.is_empty();
    let mut detail = format!("{} chosen by {selected_by}", resolved.display());
    if others.is_empty() {
        detail.push_str("; no other vault is visible");
    } else {
        detail.push_str(&format!(
            "; {} other vault(s) visible: {}",
            others.len(),
            others.join(", ")
        ));
    }
    if ambiguous {
        detail.push_str("; set SKARBIEC_VAULT_FILE to say which one is meant");
    }
    if orphan_default {
        detail.push_str(&format!(
            "; a vault sits at the default path {} with no {ROUTES_TABLE} beside it, so every resource the broker is asked to resolve there would map to nothing",
            default.display()
        ));
    }

    let mut entry = check(
        "selection",
        if ambiguous || orphan_default {
            FAIL
        } else {
            PASS
        },
        detail,
    );
    entry["resolved"] = json!(resolved.display().to_string());
    entry["selected_by"] = json!(selected_by);
    entry["candidates"] = json!(visible);
    entry
}

/// The path `vault_path` falls back to, computed the same way it computes it.
fn default_vault_path() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".local/share/skarbiec/skarbiec.vault.json")
}
