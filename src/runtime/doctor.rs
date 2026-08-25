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
use std::collections::HashMap;

use crate::credential;
use crate::runtime::audit;

/// Verdicts a check can return.
///
/// `not_configured` is separate from `fail` on purpose: a fresh install has
/// configured no WORM receipts, and reporting that as a failure is how a
/// dashboard teaches its operator that red means nothing.
const PASS: &str = "pass";
const FAIL: &str = "fail";
const NOT_CONFIGURED: &str = "not_configured";

/// Digests recomputed for the newest entries. Linkage covers the whole journal;
/// the bounded window keeps routine diagnosis proportional to a fixed tail.
const DIGEST_WINDOW: &str = "200";

fn check(name: &str, status: &str, detail: String) -> Value {
    json!({"check": name, "status": status, "detail": detail})
}

/// The vault, read as a file rather than asked over HTTP.
fn vault_check() -> Value {
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
fn audit_check() -> Value {
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

/// The canonical endpoint, resolved from its file and probed with a connect.
fn endpoint_check() -> Value {
    match credential::canonical_endpoint_report() {
        Ok(report) => {
            let endpoint = report
                .get("endpoint")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let forward = report
                .get("forward")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let answering = report
                .get("answering")
                .and_then(Value::as_bool)
                .unwrap_or_default();
            if answering {
                check(
                    "endpoint",
                    PASS,
                    format!("{endpoint}, declared by {forward}"),
                )
            } else {
                check(
                    "endpoint",
                    FAIL,
                    format!("nothing answers {endpoint}, declared by {forward}"),
                )
            }
        }
        Err(error) => check("endpoint", NOT_CONFIGURED, error.to_string()),
    }
}

/// Write-once receipts, which nobody configures by default.
fn worm_check() -> Value {
    let directory = std::env::var("SKARBIEC_WORM_RECEIPT_DIR").unwrap_or_default();
    let checkpoint = std::env::var("SKARBIEC_WORM_CHECKPOINT").unwrap_or_default();
    if directory.trim().is_empty() || checkpoint.trim().is_empty() {
        return check(
            "worm",
            NOT_CONFIGURED,
            "set SKARBIEC_WORM_RECEIPT_DIR and SKARBIEC_WORM_CHECKPOINT to enable write-once receipts".to_string(),
        );
    }
    let missing: Vec<&str> = [directory.as_str(), checkpoint.as_str()]
        .into_iter()
        .filter(|path| !std::path::Path::new(path).exists())
        .collect();
    if missing.is_empty() {
        check("worm", PASS, format!("receipts in {directory}"))
    } else {
        check(
            "worm",
            FAIL,
            format!("configured but absent: {}", missing.join(", ")),
        )
    }
}

/// Every check, plus a tally an operator can read at a glance.
pub fn report() -> Result<Value> {
    let checks = vec![vault_check(), audit_check(), endpoint_check(), worm_check()];
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
