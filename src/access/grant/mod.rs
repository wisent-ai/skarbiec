// The declared consumer grant: one capability, one grammar, six leaves.
//
// A grant is one declaration the v2 validator already enforces -- an action,
// one item, an optional exact field, and, for `acquire`, the Ed25519 workload
// public key that action requires. `grant issue` writes that declaration,
// `grant capability` issues one bounded redemption of an existing one,
// `grant ensure` widens one by a single exact field read, `grant list` reports
// them, `grant verify` asks one exact question, and `grant revoke` withdraws.
//
// Six leaves replaced seven verbs -- `token-mint`, `token-ensure-read`,
// `token-revoke`, `token-verify`, `tokens`, `capability-issue` and `invite` --
// each of which restated this grammar by hand, so each was another place an
// operator could be told a different answer to what a grant is. `invite` was
// `token-mint` with one acquire capability spelled out in order to print a
// redemption contract; that contract is what `grant issue` now answers with
// whenever the grant it wrote is workload-bound.
//
// Long-lived grants authenticate a consumer; workload-bound `acquire`
// capabilities may only mint a short-lived, field-bound, single-use bearer
// through the acquisition module.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;



mod issue;
mod leaves;
mod lookup;
mod rules;

pub(crate) use lookup::live_grants;
pub use lookup::{
    introspect, presented_hash, token_allows_action, token_allows_any_item_hash,
    token_allows_field_action, token_allows_vault_action, token_valid_hash,
};
pub use rules::capabilities::acquisition_workload_public_key;

use leaves::group;
use lookup::{load, now_epoch};
use rules::capabilities::{parse_capabilities, read_acquisition_catalog};
use rules::validation::read_workload_public_key;


pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "token-register-acquisitions" => {
            let catalog = positionals.first().context(
                "usage: token-register-acquisitions <absolute-catalog> --workload-public-key-file PATH [--ttl-seconds N] [--replace-capabilities]",
            )?;
            let allowed_flags = [
                "workload-public-key-file",
                "ttl-seconds",
                "replace-capabilities",
            ];
            if flags
                .keys()
                .any(|flag| !allowed_flags.contains(&flag.as_str()))
            {
                bail!("unsupported token-register-acquisitions flag");
            }
            let public_key_path = flags
                .get("workload-public-key-file")
                .context("--workload-public-key-file is required")?;
            let workload_public_key = read_workload_public_key(Path::new(public_key_path))?;
            let ttl_seconds: u64 = flags
                .get("ttl-seconds")
                .map(String::as_str)
                .unwrap_or("2592000")
                .parse()
                .context("--ttl-seconds must be an integer")?;
            if ttl_seconds == u64::MIN {
                bail!("--ttl-seconds must be positive");
            }
            let expires_at = now_epoch()?
                .checked_add(ttl_seconds)
                .context("grant expiry overflow")?;
            let replace = flags
                .get("replace-capabilities")
                .is_some_and(|value| value == "true");
            let rows = read_acquisition_catalog(Path::new(catalog))?;
            let mut vault = load()?;
            let mut registrations = Vec::new();
            for (consumer, item, field) in &rows {
                let capabilities =
                    parse_capabilities(&vault, &format!("acquire:{item}#{field}"), &[])?;
                if let Some(existing) = vault
                    .doc()
                    .get("tokens")
                    .and_then(Value::as_object)
                    .and_then(|tokens| tokens.get(consumer))
                {
                    let same_capabilities = existing.get("capabilities").and_then(Value::as_array)
                        == Some(&capabilities);
                    let same_key = existing.get("workload_public_key").and_then(Value::as_str)
                        == Some(workload_public_key.as_str());
                    if (!same_capabilities || !same_key) && !replace {
                        bail!(
                            "{consumer} differs from the acquisition catalog; pass --replace-capabilities"
                        );
                    }
                }
                registrations.push((consumer.clone(), capabilities));
            }
            let tokens = vault
                .doc_mut()
                .get_mut("tokens")
                .and_then(Value::as_object_mut)
                .context("tokens section")?;
            for (consumer, capabilities) in &registrations {
                tokens.insert(
                    consumer.clone(),
                    json!({
                        "hash": Value::Null,
                        "capabilities": capabilities,
                        "workload_public_key": workload_public_key,
                        "audience": consumer,
                        "expires_at": expires_at,
                    }),
                );
            }
            vault.save()?;
            crate::runtime::audit::append(
                "token-register-acquisitions",
                &json!({
                    "consumers": registrations.iter().map(|(consumer, _)| consumer).collect::<Vec<_>>(),
                    "expires_at": expires_at,
                }),
            )?;
            Ok(Some(json!({
                "ok": true,
                "registered": registrations.len(),
                "expires_at": expires_at,
            })))
        }
        "grant" => group(flags, positionals),
        _ => Ok(None),
    }
}


