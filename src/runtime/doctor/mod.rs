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
mod services;
mod vault;

use access::{credentials_check, grants_check};
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

/// Digests recomputed for the newest entries. Linkage covers the whole journal;
/// the bounded window keeps routine diagnosis proportional to a fixed tail.
pub(super) const DIGEST_WINDOW: &str = "200";

pub(super) fn check(name: &str, status: &str, detail: String) -> Value {
    json!({"check": name, "status": status, "detail": detail})
}

/// Every check, plus a tally an operator can read at a glance.
pub fn report() -> Result<Value> {
    let checks = vec![
        vault_check(),
        selection_check(),
        audit_check(),
        endpoint_check(),
        worm_check(),
        grants_check(),
        credentials_check(),
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

/// Repair the GnuPG daemons and say what happened, as a receipt.
///
/// `doctor` reports; this acts, because the state it repairs is the one that
/// makes every other check unreadable: a wedged keyboxd answers
/// `keydb_search failed: Broken pipe` and the vault then refuses reads of
/// items whose keys are present, which reads downstream as unreachable
/// infrastructure. The receipt names the daemons, so a caller sees the same
/// three names the escalation uses rather than a bare success.
pub fn recover_daemons() -> Result<Value> {
    let outcome = crate::core::crypto::recover_daemons();
    let recovered = outcome.is_ok();
    let detail = outcome.err().map(|error| format!("{error:#}"));
    Ok(json!({
        "recovered": recovered,
        "daemons": ["keyboxd", "gpg-agent", "scdaemon"],
        "detail": detail,
    }))
}
