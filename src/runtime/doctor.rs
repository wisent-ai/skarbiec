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

use crate::access::tokens;
use crate::core::{schema, vault::Vault, vault_path};
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

/// Actions whose resource is a vault item.
///
/// The rest name something else in the same slot and have no item to check:
/// `call` names a service and a route inside it, `sync` names the replication
/// channel as `sync:pull`, `enroll` names a recipient uid, and `introspect`
/// names the token table. `token-mint` already declines to resolve those
/// against the vault for the same reason.
fn names_vault_item(action: &str) -> bool {
    matches!(
        action,
        "acquire"
            | "read"
            | "stage"
            | "rotate"
            | "verify"
            | "revoke"
            | "share"
            | "trash"
            | "purge"
            | "admin"
            | "donate"
            | "lifecycle"
            | "reseal"
    )
}

/// One grant against the vault, in `routes verify`'s words.
///
/// The first two problems are that command's own strings, because a broken
/// grant and a broken route are the same failure seen from two tables and an
/// operator should not have to learn it twice. The third is new, and is
/// deliberately a question about the kind rather than about the value: a
/// `stage` or `acquire` capability may name a field that does not exist yet,
/// since staging is how that field comes to exist, so demanding presence would
/// report every legitimate provisioning grant as broken. What can never be
/// right is a capability naming a field the item's kind refuses outright --
/// that grant cannot be satisfied by any future write.
///
/// Nothing is decrypted. `state` and `kind` sit in cleartext beside the
/// ciphertext, which is what keeps this proportional across a catalog of a
/// hundred-odd grants and keeps it answering on a host whose gpg is the fault.
fn grant_problem(vault: &Vault, item: &str, field: Option<&str>) -> Option<String> {
    let Some(record) = vault.doc().get("items").and_then(|items| items.get(item)) else {
        return Some(format!("no vault item {item}"));
    };
    if record.get("state").and_then(Value::as_str) == Some("trashed") {
        return Some(format!("vault item {item} is in trash"));
    }
    let field = field?;
    let kind = record.get("kind").and_then(Value::as_str).unwrap_or_default();
    if !schema::kind_allows_field(kind, field) {
        return Some(format!(
            "vault item {item} kind {kind} does not allow the {field} field"
        ));
    }
    None
}

/// The capability as its own grammar writes it, so an operator can paste the
/// reported row straight back into `token-mint`.
fn written_capability(action: &str, item: &str, field: Option<&str>) -> String {
    match field {
        Some(field) => format!("{action}:{item}#{field}"),
        None => format!("{action}:{item}"),
    }
}

/// Consumer grants, against the vault they name.
///
/// The other four checks cover storage, the journal, the endpoint and receipts,
/// and none of them looks at the access plane. Nothing else does either: a
/// grant whose item was trashed, purged or renamed away, or one naming a field
/// its kind refuses, stays silent until a workload fails at runtime with an
/// `unauthorized` that names no cause -- and `unauthorized` is deliberately the
/// same word for every refusal, so the workload cannot tell drift from a
/// genuine denial. This is that drift, named where it happened.
fn grants_check() -> Value {
    let vault = match Vault::open(vault_path()) {
        Ok(vault) => vault,
        Err(error) => return check("grants", FAIL, format!("{}: {error}", vault_path().display())),
    };
    let mut checked = usize::MIN;
    let mut problems = Vec::new();
    for (consumer, capabilities) in tokens::live_grants(&vault) {
        for capability in capabilities {
            let (Some(action), Some(item)) = (
                capability.get("action").and_then(Value::as_str),
                capability.get("item").and_then(Value::as_str),
            ) else {
                continue;
            };
            if !names_vault_item(action) {
                continue;
            }
            let field = capability.get("field").and_then(Value::as_str);
            checked = checked.saturating_add(std::iter::once(()).count());
            let Some(problem) = grant_problem(&vault, item, field) else {
                continue;
            };
            problems.push(json!({
                "consumer": consumer,
                "capability": written_capability(action, item, field),
                "problem": problem,
            }));
        }
    }
    // A fresh install has registered no consumer, exactly as it has configured
    // no WORM receipts, and an install with only `call` or `sync` grants names
    // no vault coordinate to be wrong about. Neither is an outage.
    if checked == usize::MIN {
        return check(
            "grants",
            NOT_CONFIGURED,
            "no live consumer grant names a vault item".to_string(),
        );
    }
    if problems.is_empty() {
        return check("grants", PASS, format!("{checked} grants resolve"));
    }
    let mut entry = check(
        "grants",
        FAIL,
        format!("{} of {checked} grants broken", problems.len()),
    );
    entry["problems"] = json!(problems);
    entry
}

/// Every check, plus a tally an operator can read at a glance.
pub fn report() -> Result<Value> {
    let checks = vec![
        vault_check(),
        audit_check(),
        endpoint_check(),
        worm_check(),
        grants_check(),
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
