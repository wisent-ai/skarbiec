// What the vault itself answers: which file was selected, whether it opens,
// and whether the journal beside it still links.

use crate::core::vault_path;
use crate::runtime::{audit, vaults};
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{check, FAIL, NOT_CONFIGURED, PASS};

/// The vault, read as a file rather than asked over HTTP.
pub(super) fn vault_check() -> Value {
    let path = crate::core::vault_path();
    match crate::core::items::status_json() {
        Ok(status) => {
            let items = status.get("item_count").and_then(Value::as_u64);
            let grants = match status.get("token_count").and_then(Value::as_u64) {
                Some(count) => format!("{count} grants"),
                None => "no grant count reported".to_string(),
            };
            match items {
                Some(count) => check(
                    "vault",
                    PASS,
                    format!("{count} items, {grants}, at {}", path.display()),
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

/// The hash chain, split the way `audit verify` splits it: linkage over the
/// whole journal, digests over the newest `tail` entries or over all of them.
pub(super) fn audit_check(tail: Option<&str>) -> Value {
    let mut flags = HashMap::new();
    if let Some(tail) = tail {
        flags.insert("tail".to_string(), tail.to_string());
    }
    match audit::chain_report(&flags) {
        Ok(report) => {
            let (linked, total, digests, journal) = (
                report.linkage_verified,
                report.linkage_checked,
                report.digests_verified,
                &report.journal,
            );
            let detail = if report.intact {
                format!("{linked} of {total} entries linked, newest {digests} digests intact, in {journal}")
            } else {
                // Each fault carries its line and the entry's instant, null
                // for a line too malformed to state one; printed as recorded.
                let first = match report.faults.first() {
                    Some(fault) => format!("line {} ({})", fault["line"], fault["at"]),
                    None => "an unreported position".to_string(),
                };
                format!(
                    "{linked} of {total} entries linked, newest {digests} digests intact; {} fault(s), first at {first}, in {journal}",
                    report.faults.len()
                )
            };
            check("audit", if report.intact { PASS } else { FAIL }, detail)
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
/// `SKARBIEC_VAULT_FILE`, then the vault Stado declares for this machine,
/// then falls back to `$HOME/.local/share/skarbiec`, and the fallback is
/// silent: a bare `skarbiec` on a host holding several vaults and no
/// declaration picks the first search path and says nothing about the
/// others. That silence is how a vault written by an unpinned command
/// becomes the default answer for every command afterwards,
/// indistinguishable at the surface from the vault an operator believes they
/// are running.
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
    let declaration = crate::core::stado_config_file();
    let (selected_by, explicit) = if std::env::var_os("SKARBIEC_VAULT_FILE").is_some() {
        ("SKARBIEC_VAULT_FILE".to_string(), true)
    } else {
        match (crate::core::stado_declared_vault(), declaration.as_deref()) {
            (Ok(Some(_)), Some(file)) => (
                format!(
                    "Stado's declaration secrets.skarbiec.vault_file in {}",
                    file.display()
                ),
                true,
            ),
            (Ok(Some(_)), None) => (
                "Stado's declaration secrets.skarbiec.vault_file".to_string(),
                true,
            ),
            (Ok(None), _) => ("the HOME fallback".to_string(), false),
            (Err(cause), _) => (format!("the HOME fallback, because {cause}"), false),
        }
    };

    // A vault the inventory could not read, or an inventory that failed, is
    // said beside the visible ones: read as none, the doctor called a choice
    // unambiguous that another, unreadable vault might contest.
    let (visible, unread): (Vec<Value>, Vec<String>) = match vaults::inventory() {
        Ok(report) => (
            report["vaults"]
                .as_array()
                .into_iter()
                .flatten()
                .cloned()
                .collect(),
            report["unreadable"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|entry| format!("{} {}", entry["path"], entry["cause"]))
                .collect(),
        ),
        // No vault is listed as visible, and the failure is the one unread
        // entry, so the selection below is never called unambiguous.
        Err(error) => (
            Vec::new(),
            vec![format!("the vault inventory failed: {error}")],
        ),
    };
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
        entry["unreadable"] = json!(unread);
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
    if !unread.is_empty() {
        detail.push_str(&format!("; not read: {}", unread.join("; ")));
    }
    if ambiguous {
        detail.push_str("; declare it: `stado config set secrets.skarbiec.vault_file <path>`, or set SKARBIEC_VAULT_FILE for one process");
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
    crate::core::default_vault_path()
}
