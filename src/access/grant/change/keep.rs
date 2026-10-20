// Keeping a grant: the grant a consumer already holds is made to live until
// `grant revoke` withdraws it. Its capabilities, its audience and the hash of
// the bearer the consumer holds stay as they were, so nothing has to be
// delivered to the machine that holds the bearer: re-issuing would rotate a
// bearer that lives on another host, or need its file here.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::access::grant::lookup::load;
use crate::access::grant::rules::validation::exact_component;
use crate::access::grant::UNTIL_REVOKED;
use crate::core::vault_path;

/// Make `consumer`'s grant live until revoked. A consumer without a grant is
/// refused by name, and so are an acquire grant, which lends its lifetime to
/// every bearer it mints, and a grant that records no bearer; a grant that
/// already lives until revoked is reported `unchanged` and the vault is not
/// written, so a repeated keep changes nothing. A lapsed grant is kept too:
/// what ended it was a clock, not a revocation.
pub(in crate::access::grant) fn keep_once(consumer: &str) -> Result<Value> {
    if !exact_component(consumer) {
        bail!("grant keep requires one exact consumer name");
    }
    let mut vault = load()?;
    let grant = vault
        .doc_mut()
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .and_then(|tokens| tokens.get_mut(consumer))
        .with_context(|| {
            format!(
                "consumer {consumer} has no grant in {}",
                vault_path().display()
            )
        })?;
    let acquire = grant
        .get("capabilities")
        .and_then(Value::as_array)
        .context("existing grant is not v2; run `skarbiec upgrade --apply` first")?
        .iter()
        .any(|capability| capability.get("action").and_then(Value::as_str) == Some("acquire"));
    if acquire {
        bail!(
            "consumer {consumer} holds an acquire grant, which lends its lifetime to every \
             bearer it mints, so it keeps the lifetime it was issued with"
        );
    }
    if grant.get("hash").and_then(Value::as_str).is_none() {
        bail!(
            "consumer {consumer}'s grant records no bearer, so a consumer holds nothing it could \
             keep presenting; issue it with `grant issue`"
        );
    }
    let previous = grant
        .get("expires_at")
        .cloned()
        .with_context(|| format!("consumer {consumer}'s grant records no expires_at"))?;
    if previous.as_u64() == Some(UNTIL_REVOKED) {
        return Ok(json!({
            "ok": true,
            "consumer": consumer,
            "status": "unchanged",
            "expires_at": previous,
            "decided_against_vault": vault_path().display().to_string(),
        }));
    }
    grant["expires_at"] = json!(UNTIL_REVOKED);
    vault.save()?;
    crate::runtime::audit::append(
        "grant-kept",
        &json!({ "consumer": consumer, "previous_expires_at": previous }),
    )?;
    Ok(json!({
        "ok": true,
        "consumer": consumer,
        "status": "kept",
        "previous_expires_at": previous,
        "expires_at": UNTIL_REVOKED,
        "decided_against_vault": vault_path().display().to_string(),
    }))
}
