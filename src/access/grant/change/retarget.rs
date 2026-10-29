// Retargeting a grant: every capability that names one item is moved to
// another, keeping its action and field, the bearer and the lifetime. A
// rename leaves grants naming the old id; this is how such a grant follows
// the item without the consumer receiving a new bearer.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::access::grant::lookup::load;
use crate::access::grant::rules::capabilities::parse_capabilities;
use crate::access::grant::rules::validation::{exact_component, exact_resource};
use crate::core::vault_path;

/// Move `consumer`'s capabilities naming `from` onto `to`. Each moved
/// capability is parsed again against `to`, so a field the new item's kind
/// does not declare is refused exactly as `grant issue` refuses it. A grant
/// holding nothing for `from` is reported `absent` and nothing is written.
pub(in crate::access::grant) fn retarget_once(
    consumer: &str,
    from: &str,
    to: &str,
) -> Result<Value> {
    if !exact_component(consumer) || !exact_resource(from) || !exact_resource(to) {
        bail!("grant retarget requires exact consumer, --from and --to names");
    }
    if from == to {
        bail!("--from and --to both name {from}; there is nothing to move");
    }
    let mut vault = load()?;
    let held: Vec<Value> = vault
        .doc()
        .get("tokens")
        .and_then(|tokens| tokens.get(consumer))
        .with_context(|| {
            format!(
                "consumer {consumer} has no grant in {}",
                vault_path().display()
            )
        })?
        .get("capabilities")
        .and_then(Value::as_array)
        .context("existing grant is not v2; run `skarbiec upgrade --apply` first")?
        .clone();
    let mut moved = Vec::new();
    let mut rewritten = Vec::new();
    for capability in held {
        if capability.get("item").and_then(Value::as_str) != Some(from) {
            rewritten.push(capability);
            continue;
        }
        let action = capability
            .get("action")
            .and_then(Value::as_str)
            .with_context(|| {
                format!("a capability of {consumer} naming {from} records no action")
            })?;
        let encoded = match capability.get("field").and_then(Value::as_str) {
            Some(field) => format!("{action}:{to}#{field}"),
            None => format!("{action}:{to}"),
        };
        let mut parsed = parse_capabilities(&vault, &encoded, &[]).with_context(|| {
            format!("{encoded} cannot replace {consumer}'s capability on {from}")
        })?;
        let replacement = parsed
            .pop()
            .with_context(|| format!("{encoded} parsed to no capability"))?;
        if !rewritten.contains(&replacement) {
            rewritten.push(replacement.clone());
        }
        moved.push(replacement);
    }
    if moved.is_empty() {
        return Ok(json!({
            "ok": true,
            "consumer": consumer,
            "status": "absent",
            "moved": moved,
            "decided_against_vault": vault_path().display().to_string(),
        }));
    }
    *vault
        .doc_mut()
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .and_then(|tokens| tokens.get_mut(consumer))
        .and_then(|grant| grant.get_mut("capabilities"))
        .with_context(|| {
            format!("consumer {consumer}'s capabilities went missing while they were rewritten")
        })? = json!(rewritten);
    vault.save()?;
    crate::runtime::audit::append(
        "grant-retargeted",
        &json!({"consumer": consumer, "from": from, "to": to, "moved": moved.len()}),
    )?;
    Ok(json!({
        "ok": true,
        "consumer": consumer,
        "status": "moved",
        "moved": moved,
        "decided_against_vault": vault_path().display().to_string(),
    }))
}
