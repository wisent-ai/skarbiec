// What a caller would actually be allowed to do: every live grant checked
// against the item it names, and every capability route checked against the
// credential it resolves to.

use serde_json::{json, Value};
use crate::access::grant;
use crate::access::route::{resolution as route_resolution, table as route_table};
use crate::core::vault::Vault;
use crate::core::{schema, vault_path};

use super::{check, FAIL, NOT_CONFIGURED, PASS};

/// Actions whose resource is a vault item.
///
/// The rest name something else in the same slot and have no item to check:
/// `call` names a service and a route inside it, `sync` names the replication
/// channel as `sync:pull`, `enroll` names a recipient uid, and `introspect`
/// names the token table. `grant issue` already declines to resolve those
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

/// One grant against the vault, in `route verify`'s words.
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
    let kind = record
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !schema::kind_allows_field(kind, field) {
        return Some(format!(
            "vault item {item} kind {kind} does not allow the {field} field"
        ));
    }
    None
}

/// The capability as its own grammar writes it, so an operator can paste the
/// reported row straight back into `grant issue`.
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
pub(super) fn grants_check() -> Value {
    let vault = match Vault::open(vault_path()) {
        Ok(vault) => vault,
        Err(error) => {
            return check(
                "grants",
                FAIL,
                format!("{}: {error}", vault_path().display()),
            )
        }
    };
    let mut checked = usize::MIN;
    let mut problems = Vec::new();
    for (consumer, capabilities) in grant::live_grants(&vault) {
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

/// Capability routes, against the credentials they promise.
///
/// `grants` asks whether a consumer is allowed to reach a coordinate. This
/// asks the question underneath it, the one nothing in this crate ever asked
/// automatically: does the credential that coordinate names actually hold a
/// value? A route can be present, its item live, its field named and its
/// grant in order, and the field still hold nothing -- and every surface
/// reported that as healthy until the gateway needing the credential could not
/// obtain one, failed to become ready, and had its release quarantined
/// eighteen times over a month with "candidate did not become ready" recorded
/// each time and the cause recorded never.
///
/// The verdict comes from `route verify`'s own resolver, not a second opinion
/// about what a usable credential is: the item is live and readable, and the
/// field is neither blank nor an uppercase placeholder.
///
/// Unlike `grants` this one decrypts, because content is not a question the
/// cleartext envelope can answer. That is one gpg per distinct item, and the
/// resolver opens each item once however many resources map onto it.
pub(super) fn credentials_check() -> Value {
    // No table is a fresh install, exactly as no WORM receipt is: the broker
    // resolves nothing yet and there is no credential to be wrong about.
    let path = route_table::table_path();
    if !path.exists() {
        return check(
            "credentials",
            NOT_CONFIGURED,
            format!("no capability routes table at {}", path.display()),
        );
    }
    let rows = match route_resolution::verdicts(None) {
        Ok(rows) => rows,
        Err(error) => return check("credentials", FAIL, format!("{}: {error}", path.display())),
    };
    // A table that parses but maps nothing resolves nothing, and there is
    // still no credential to be wrong about.
    if rows.is_empty() {
        return check(
            "credentials",
            NOT_CONFIGURED,
            format!("no capability route in {}", path.display()),
        );
    }
    let problems: Vec<Value> = rows
        .iter()
        .filter_map(|row| {
            row.problem.as_ref().map(|problem| {
                json!({
                    "resource": row.resource,
                    "item": row.item,
                    "field": row.field,
                    "problem": problem,
                })
            })
        })
        .collect();
    if problems.is_empty() {
        return check(
            "credentials",
            PASS,
            format!("{} routes hold a usable credential", rows.len()),
        );
    }
    let mut entry = check(
        "credentials",
        FAIL,
        format!(
            "{} of {} routes cannot serve a credential",
            problems.len(),
            rows.len()
        ),
    );
    entry["problems"] = json!(problems);
    entry
}
