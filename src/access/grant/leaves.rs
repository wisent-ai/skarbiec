// The six leaves of the `grant` group: issue, capability, ensure, list,
// verify and revoke, plus the help that names them.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use super::issue::{ensure_read_once, issue_once};
use super::lookup::{load, token_allows_action, token_allows_field_action};
use super::rules::validation::{exact_component, read_fixed_token};

/// The six leaves of the `grant` group.
///
/// The subcommand is the first positional and every leaf reads the rest, so the
/// argument list of a leaf is the one its replaced verb took: what moved is the
/// name, not the grammar.
pub(in crate::access::grant) fn group(
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    let subcommand = positionals.first().map(String::as_str).unwrap_or("help");
    let positionals = positionals
        .get(std::iter::once(()).count()..)
        .unwrap_or_default();
    match subcommand {
        // A bounded, use-counted redemption of a declaration that already
        // exists: the resource resolves through the capability-route table and
        // the workload key comes from the consumer grant, so nothing new is
        // declared here. `capability-serve` is the surface that spends it.
        "capability" => Ok(Some(crate::access::capability::issue(flags)?)),
        "ensure" => {
            let consumer = positionals.first().context(
                "usage: grant ensure <consumer> <item> --field <field> --token-file <path>",
            )?;
            let item = positionals.get(std::iter::once(()).count()).context(
                "usage: grant ensure <consumer> <item> --field <field> --token-file <path>",
            )?;
            let field = flags.get("field").context("--field is required")?;
            let token_file = flags
                .get("token-file")
                .map(Path::new)
                .context("--token-file is required")?;
            let mut attempt = 0u32;
            loop {
                attempt += 1;
                match ensure_read_once(consumer, item, field, token_file) {
                    Ok(report) => return Ok(Some(report)),
                    Err(error)
                        if error.to_string().contains("changed concurrently") && attempt < 5 =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(
                            150 * u64::from(attempt),
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        "issue" => {
            let consumer = positionals
                .first()
                .context("usage: grant issue <consumer> --capabilities action:item[#field]")?;
            if !exact_component(consumer) {
                bail!("consumer must be one exact name");
            }
            // Many hosts mint concurrently against one authoritative vault.
            // save() is optimistic and refuses on generation drift, so a
            // losing racer re-opens and re-applies instead of surfacing
            // the conflict to callers. Every attempt mints a fresh bearer;
            // only the winner's bearer lands in the report.
            let mut attempt = 0u32;
            loop {
                attempt += 1;
                match issue_once(consumer, flags, attempt) {
                    Ok(report) => return Ok(Some(report)),
                    Err(error)
                        if error.to_string().contains("changed concurrently") && attempt < 5 =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(
                            150 * u64::from(attempt),
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        "revoke" => {
            let consumer = positionals
                .first()
                .context("usage: grant revoke <consumer>")?;
            let mut vault = load()?;
            vault
                .doc_mut()
                .get_mut("tokens")
                .and_then(Value::as_object_mut)
                .context("tokens section")?
                .remove(consumer);
            vault.save()?;
            crate::runtime::audit::append("grant-revoked", &json!({"consumer": consumer}))?;
            Ok(Some(json!({"ok": true, "consumer": consumer})))
        }
        "verify" => {
            let consumer = positionals.first().context(
                "usage: grant verify <consumer> <item> [--action <action>] [--field <field>] --token <bearer>",
            )?;
            let item = positionals.get(std::iter::once(()).count()).context(
                "usage: grant verify <consumer> <item> [--action <action>] [--field <field>] --token <bearer>",
            )?;
            let action = flags.get("action").map(String::as_str).unwrap_or("read");
            let presented = &match (flags.get("token"), flags.get("token-file")) {
                (Some(_), Some(_)) => bail!("grant verify takes --token or --token-file, not both"),
                (Some(token), None) => token.to_string(),
                (None, Some(path)) => read_fixed_token(Path::new(path))?,
                (None, None) => bail!("grant verify requires --token or --token-file"),
            };
            let allowed = match flags.get("field") {
                Some(field) => {
                    token_allows_field_action(&load()?, consumer, presented, action, item, field)?
                }
                None => token_allows_action(&load()?, consumer, presented, action, item)?,
            };
            Ok(Some(json!({
                "consumer": consumer,
                "action": action,
                "item": item,
                "field": flags.get("field"),
                "allowed": allowed,
            })))
        }
        "list" => {
            let vault = load()?;
            let listing: Vec<Value> = vault
                .doc()
                .get("tokens")
                .and_then(Value::as_object)
                .map(|tokens| {
                    tokens
                        .iter()
                        .map(|(consumer, entry)| {
                            json!({
                                "consumer": consumer,
                                "capabilities": entry.get("capabilities"),
                                "workload_bound": entry
                                    .get("workload_public_key")
                                    .and_then(Value::as_str)
                                    .is_some(),
                                "audience": entry.get("audience"),
                                "expires_at": entry.get("expires_at"),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(Some(json!(listing)))
        }
        "help" => Ok(Some(json!({
            "commands": [
                "grant issue <consumer> --capabilities <action:item[#field],...> [--workload-public-key-file <path>] [--token-file <path>] [--ttl-seconds <N>] [--audience <name>] [--replace-capabilities]",
                "grant capability --agent <name> --purpose <text> --resource <resource> --target <name> [--ttl <seconds>] [--max-uses <1..16>] [--authorization-id <id>]",
                "grant ensure <consumer> <item> --field <field> --token-file <path>",
                "grant list",
                "grant verify <consumer> <item> [--action <action>] [--field <field>] --token <bearer> | --token-file <path>",
                "grant revoke <consumer>",
            ],
            "usage": "A grant is one declaration: an action, one item, an optional exact field, and the Ed25519 workload public key an acquire capability requires. grant issue writes that declaration and rotates the bearer of that consumer, refusing a changed capability set unless the call states --replace-capabilities; an acquire grant returns no bearer at all and answers instead with the acquisition redemption contract for every exact coordinate it names. grant capability issues one bounded, use-counted redemption of a grant already declared, against a resource the capability-route table maps to a vault field, and refuses at issue time when that route is missing or the credential behind it cannot serve; capability-serve is what redeems it. grant ensure widens an existing direct grant by one exact field read without rotating anything, the owner proving possession through a mode-0600 --token-file that must hash to the recorded bearer. grant list returns metadata only, never a bearer and never a workload public key. grant verify answers one exact action, item and optional field question about one presented bearer, taken from --token or from an owner-only --token-file. grant revoke drops the whole declaration and is idempotent.",
            "actions": [
                "read", "acquire", "stage", "rotate", "verify", "revoke", "share", "trash",
                "purge", "admin", "sync", "enroll", "donate", "lifecycle", "reseal",
                "introspect", "call",
            ],
        }))),
        other => bail!("unknown grant command: {other}"),
    }
}
