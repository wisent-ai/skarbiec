// Diagnosis that still works when the product does not.
//
// `docs/PRODUCT.md` lists `<product> doctor` among the required surfaces and
// fixes its one hard rule: it "reads state directly, never through the API it
// is diagnosing". That rule is the whole value. An evening was spent here
// diagnosing this vault with `curl` against guessed routes, concluding from
// two 404s that nothing on the fleet served Skarbiec at all - when the real
// answer was that `/v1/items/list` is a POST and the health route is
// `/health`, not `/healthz`. Every check below opens a file or a socket.
//
// The checks are the ones the desktop Overview renders, so an operator can
// get the same answer without a window, and the two surfaces cannot drift.

use anyhow::Result;
use serde_json::{json, Value};

mod access;
mod daemons;
mod helpers;
mod services;
mod vault;

use access::{credentials_check, grants_check};
use daemons::daemons_check;
use services::{endpoint_check, worm_check};
use vault::{audit_check, selection_check, vault_check};

/// Verdicts a check can return.
///
/// `not_configured` is separate from `fail` on purpose: a fresh install has
/// configured no WORM receipts, and reporting that as a failure is how a
/// dashboard teaches its operator that red means nothing.
pub(super) const PASS: &str = "pass";
pub(super) const FAIL: &str = "fail";
pub(super) const NOT_CONFIGURED: &str = "not_configured";

pub(super) fn check(name: &str, status: &str, detail: String) -> Value {
    json!({"check": name, "status": status, "detail": detail})
}

/// Whether the Git ciphertext mirror carries the live vault: a host whose
/// mirror stopped being pushed keeps an ever older recovery copy, and nothing
/// else says so until the copy is needed.
fn mirror_check() -> Value {
    match crate::net::sync::published_state() {
        None => check(
            "mirror",
            NOT_CONFIGURED,
            "no Git mirror on this host".into(),
        ),
        Some(Ok(detail)) => check("mirror", PASS, detail),
        Some(Err(detail)) => check("mirror", FAIL, detail),
    }
}

/// Whether the autofill extension can offer every live login on this
/// machine: a login added after the browser host's grant was minted is one
/// the extension lists as unreadable until `browser cover` or the next
/// `maintain` widens the grant.
fn autofill_check() -> Value {
    match crate::browser::autofill_reach() {
        Err(error) => check("autofill", FAIL, format!("{error:#}")),
        Ok(None) => check(
            "autofill",
            NOT_CONFIGURED,
            "browser autofill is not connected on this machine".into(),
        ),
        Ok(Some(missing)) if missing.is_empty() => {
            check("autofill", PASS, "the extension can offer every live login".into())
        }
        Ok(Some(missing)) => check(
            "autofill",
            FAIL,
            format!(
                "the extension cannot offer {}; run skarbiec browser cover, or let the next maintain pass cover them",
                missing.join(", ")
            ),
        ),
    }
}

/// Whether every key the vault writes to can still be written to: a write,
/// share or revoke encrypts to all of them, so one expired, revoked or
/// missing key stops every change, and nothing else says why until then.
fn keys_check() -> Value {
    let answer = match crate::runtime::dispatch("keys", &std::collections::HashMap::new(), &[]) {
        Ok(Some(answer)) => answer,
        Ok(None) => return check("keys", FAIL, "the keys command answered nothing".into()),
        Err(error) => return check("keys", FAIL, format!("{error:#}")),
    };
    if answer.get("ok").and_then(Value::as_bool) == Some(true) {
        return check(
            "keys",
            PASS,
            "every key the vault writes to is in this keyring and unexpired".into(),
        );
    }
    let ended: Vec<String> = answer
        .get("keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|row| {
            row.get("in_keyring") != Some(&Value::Bool(true))
                || row.get("expired") == Some(&Value::Bool(true))
                || row.get("revoked") == Some(&Value::Bool(true))
        })
        .map(|row| match row.get("repair").and_then(Value::as_str) {
            Some(repair) => format!("{} ({repair})", row["holder"]),
            None => format!("{} (not in this keyring: import it)", row["holder"]),
        })
        .chain(
            answer
                .get("unreadable")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|row| format!("{}: {}", row["holder"], row["error"])),
        )
        .collect();
    check(
        "keys",
        FAIL,
        format!(
            "writes will fail until these keys are usable: {}",
            ended.join("; ")
        ),
    )
}

/// Whether the newest copy `backup` recorded is still where it was written
/// and still reads as a vault: a copy on a disk since unplugged, wiped or
/// overwritten is a backup in name only, and nothing else says so until the
/// day it is needed. A vault never backed up is not configured, not failed.
fn backup_check() -> Value {
    let listed = crate::runtime::dispatch(
        "audit list",
        &std::collections::HashMap::from([("op".to_string(), "vault-backed-up".to_string())]),
        &[],
    );
    let entries = match listed {
        Ok(Some(answer)) => answer
            .get("entries")
            .and_then(Value::as_array)
            .cloned()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>(),
        Ok(None) => return check("backup", FAIL, "the audit journal answered nothing".into()),
        Err(error) => return check("backup", FAIL, format!("{error:#}")),
    };
    let Some(latest) = entries.last() else {
        return check(
            "backup",
            NOT_CONFIGURED,
            "no backup recorded; skarbiec backup <directory> makes one".into(),
        );
    };
    let Some(path) = latest
        .get("extra")
        .and_then(|extra| extra.get("backup"))
        .and_then(Value::as_str)
    else {
        return check(
            "backup",
            FAIL,
            format!("the newest backup entry names no copy: {latest}"),
        );
    };
    match crate::core::vault::Vault::open(std::path::PathBuf::from(path)) {
        Ok(_) => check("backup", PASS, format!("the newest backup {path} reads as a vault (made {})", latest["at"])),
        Err(error) => check(
            "backup",
            FAIL,
            format!("the newest backup {path} would not restore: {error:#}; make another with skarbiec backup <directory>"),
        ),
    }
}

/// Every check, plus a tally an operator can read at a glance. `tail` is the
/// operator's `--tail N`: the audit digests are recomputed for the newest N
/// entries only; without it, for every entry.
pub fn report(tail: Option<&str>) -> Result<Value> {
    let checks = vec![
        vault_check(),
        selection_check(),
        audit_check(tail),
        daemons_check(),
        endpoint_check(),
        worm_check(),
        grants_check(),
        credentials_check(),
        mirror_check(),
        autofill_check(),
        keys_check(),
        backup_check(),
        helpers::helpers_check(),
        helpers::ci_secrets_check(),
        helpers::rotations_check(),
        helpers::developer_tokens_check(),
        helpers::bindings_files_check(),
    ];
    let tally = |status: &str| -> usize {
        checks
            .iter()
            .filter(|entry| entry.get("status").and_then(Value::as_str) == Some(status))
            .count()
    };
    Ok(json!({
        "checks": checks,
        "pass": tally(PASS),
        "failed": tally(FAIL),
        "not_configured": tally(NOT_CONFIGURED),
    }))
}

/// The helpers check alone, for a caller asking only which tools read their
/// credentials from this vault and what is left in plain text beside them.
pub fn helpers_report() -> Value {
    helpers::helpers_check()
}

/// `doctor --alert`: the report, and when a check failed, one message to the
/// webhook `alert set` named naming each failed check and its detail, so a
/// scheduled doctor run is seen where people look. The report carries
/// `alert`: whether a message was posted, none was needed, no alert is set,
/// or why it could not be posted.
pub fn report_alerting(tail: Option<&str>) -> Result<Value> {
    let mut answer = report(tail)?;
    let failed: Vec<String> = answer["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| entry.get("status").and_then(Value::as_str) == Some(FAIL))
        .map(|entry| format!("{}: {}", entry["check"], entry["detail"]))
        .collect();
    answer["alert"] = if failed.is_empty() {
        json!({"posted": false, "reason": "no check failed"})
    } else {
        match crate::runtime::alert::send(&format!(
            "skarbiec doctor: {} check(s) failed — {}",
            failed.len(),
            failed.join("; ")
        )) {
            Ok(Some(_)) => json!({"posted": true}),
            Ok(None) => json!({"posted": false, "reason": "no alert is set on this host"}),
            Err(error) => json!({"posted": false, "error": format!("{error:#}")}),
        }
    };
    Ok(answer)
}

/// Repair the GnuPG daemons and say what happened, as a receipt.
///
/// `doctor` reports; this acts, because the state it repairs is the one that
/// makes every other check unreadable: a wedged keyboxd answers
/// `keydb_search failed: Broken pipe` and the vault then refuses reads of
/// items whose keys are present, which reads downstream as unreachable
/// infrastructure. The receipt names the daemons, so a caller sees the same
/// three names the escalation uses rather than a bare success, and what each
/// running daemon held before it was replaced, so a bloat and a wedge read
/// differently in the same receipt.
pub fn recover_daemons() -> Result<Value> {
    let outcome = crate::core::crypto::recover_daemons();
    let recovered = outcome.is_ok();
    let (before, detail) = match outcome {
        Ok(before) => (before, None),
        Err(error) => (Vec::new(), Some(format!("{error:#}"))),
    };
    // The limit the footprints are judged against, or why it is not known:
    // a receipt that only omits it reads as "no limit applies".
    let (limit_bytes, limit_error) = match crate::core::crypto::daemon_memory_limit_bytes() {
        Ok(limit) => (Some(limit), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    Ok(json!({
        "recovered": recovered,
        "daemons": ["keyboxd", "gpg-agent", "scdaemon"],
        "before": before.iter().map(|footprint| json!({
            "daemon": footprint.daemon,
            "pid": footprint.pid,
            "bytes": footprint.bytes,
        })).collect::<Vec<_>>(),
        "limit_bytes": limit_bytes,
        "limit_error": limit_error,
        "detail": detail,
    }))
}
