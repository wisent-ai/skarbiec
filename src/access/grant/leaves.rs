// The leaves of the `grant` group: issue, capability, ensure, narrow, keep,
// list, verify and revoke, plus the help that names them.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use super::issue::{ensure_read_once, issue_once};
use super::lookup::{load, token_allows_action, token_allows_field_action};
use super::rules::validation::{exact_component, read_fixed_token};
use crate::cli::args::OrUsage;

/// The leaves of the `grant` group.
///
/// The subcommand is the first positional and every leaf reads the rest, so the
/// argument list of a leaf is the one its replaced verb took: what moved is the
/// name, not the grammar.
pub(in crate::access::grant) fn group(
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    let (subcommand, positionals) = positionals.split_first().or_usage(
        "usage: grant <issue|capability|ensure|narrow|keep|list|verify|revoke|help>",
    )?;
    let subcommand = subcommand.as_str();
    match subcommand {
        // A bounded, use-counted redemption of a declaration that already
        // exists: the resource resolves through the capability-route table and
        // the workload key comes from the consumer grant, so nothing new is
        // declared here. `serve` spends it on the host's capability socket.
        "capability" => Ok(Some(crate::access::capability::issue(flags)?)),
        "ensure" => {
            let (consumer, item) = consumer_and_item(
                positionals,
                "usage: grant ensure <consumer> <item> --field <field> --token-file <path>",
            )?;
            let field = flags.get("field").or_usage("--field is required")?;
            let token_file = flags
                .get("token-file")
                .map(Path::new)
                .or_usage("--token-file is required")?;
            loop {
                match ensure_read_once(consumer, item, field, token_file) {
                    Ok(report) => return Ok(Some(report)),
                    // A concurrent writer won; the next attempt re-reads its
                    // generation and applies on top of it.
                    Err(error) if is_concurrent_change(&error) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        "narrow" => {
            let (consumer, item) =
                consumer_and_item(positionals, "usage: grant narrow <consumer> <item> --field <field>")?;
            let field = flags.get("field").or_usage("--field is required")?;
            loop {
                match super::change::narrow_read_once(consumer, item, field) {
                    Ok(report) => return Ok(Some(report)),
                    // A concurrent writer won; the next attempt re-reads its
                    // generation and removes the capability from it.
                    Err(error) if is_concurrent_change(&error) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        "keep" => {
            let consumer = positionals
                .first()
                .or_usage("usage: grant keep <consumer>")?;
            loop {
                match super::change::keep_once(consumer) {
                    Ok(report) => return Ok(Some(report)),
                    // A concurrent writer won; the next attempt re-reads its
                    // generation and keeps the grant in it.
                    Err(error) if is_concurrent_change(&error) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        "issue" => {
            let consumer = positionals
                .first()
                .or_usage("usage: grant issue <consumer> --capabilities action:item[#field]")?;
            if !exact_component(consumer) {
                bail!("consumer must be one exact name");
            }
            // Many hosts mint concurrently against one authoritative vault.
            // save() is optimistic and refuses on generation drift, so a
            // losing racer re-opens and re-applies instead of surfacing
            // the conflict to callers. Every attempt mints a fresh bearer;
            // only the winner's bearer lands in the report.
            loop {
                match issue_once(consumer, flags) {
                    Ok(report) => return Ok(Some(report)),
                    Err(error) if is_concurrent_change(&error) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        "revoke" => {
            let consumer = positionals
                .first()
                .or_usage("usage: grant revoke <consumer>")?;
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
            let (consumer, item) = consumer_and_item(
                positionals,
                "usage: grant verify <consumer> <item> --action <action> [--field <field>] --token-file <path>",
            )?;
            // The question names its action: read, call, acquire or any other
            // the grammar knows. An unstated one is not taken to be a read.
            let action = flags.get("action").map(String::as_str).or_usage(
                "grant verify requires --action <action>: the action the bearer is asked about",
            )?;
            if flags.contains_key("token") {
                bail!(
                    "grant verify does not take --token: a bearer in argv is readable by every process on this host. \
                     Write it to an owner-only file (mode 0600) and pass --token-file <path>"
                );
            }
            let presented = &read_fixed_token(Path::new(
                flags.get("token-file").or_usage(
                    "grant verify requires --token-file <path to an owner-only file holding the bearer>",
                )?,
            ))?;
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
                .context("tokens section")?
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
                        // Said, so a reader never compares expires_at with the
                        // value that stands for "no end".
                        "until_revoked": entry.get("expires_at").and_then(Value::as_u64)
                            == Some(super::UNTIL_REVOKED),
                    })
                })
                .collect();
            Ok(Some(json!(listing)))
        }
        "help" => Ok(Some(json!({
            "commands": [
                "grant issue <consumer> --capabilities <action:item[#field],...> (--ttl-seconds <N> | --until-revoked) [--workload-public-key-file <path>] [--token-file <path>] [--audience <name>] [--replace-capabilities]",
                "grant capability --agent <name> --purpose <text> --resource <resource> --target <name> --ttl <seconds> --max-uses <N> [--authorization-id <id>]",
                "grant ensure <consumer> <item> --field <field> --token-file <path>",
                "grant narrow <consumer> <item> --field <field>",
                "grant keep <consumer>",
                "grant list",
                "grant verify <consumer> <item> --action <action> [--field <field>] --token-file <path>",
                "grant revoke <consumer>",
            ],
            "usage": "A grant is one declaration: an action, one item, an optional exact field, and the Ed25519 workload public key an acquire capability requires. grant issue writes that declaration and rotates the bearer of that consumer, refusing a changed capability set unless the call states --replace-capabilities; an acquire grant returns no bearer at all and answers instead with the acquisition redemption contract for every exact coordinate it names. grant capability issues one bounded, use-counted redemption of a grant already declared, against a resource the capability-route table maps to a vault field, and refuses at issue time when that route is missing or the credential behind it cannot serve; capability-serve is what redeems it. grant ensure widens an existing direct grant by one exact field read without rotating anything, the owner proving possession through a mode-0600 --token-file that must hash to the recorded bearer; grant narrow takes one such read out again. grant keep makes a direct grant live until revoked, keeping its capabilities and the bearer the consumer holds, so a consumer whose bearer lives on another machine needs nothing delivered; it refuses an acquire grant and a grant that records no bearer, and answers unchanged for one already kept. grant list returns metadata only, never a bearer and never a workload public key. grant verify answers one exact question, its --action stated, about one item and optional field for one bearer presented through an owner-only --token-file. grant revoke drops the whole declaration and is idempotent.",
            "actions": crate::access::actions::Action::names(),
        }))),
        other => Err(crate::cli::args::Usage(format!(
            "unknown grant command: {other}; `skarbiec grant --help` lists them"
        ))
        .into()),
    }
}

/// The consumer and item a leaf names as its two positionals; anything else
/// is refused with the leaf's usage.
fn consumer_and_item<'a>(positionals: &'a [String], usage: &str) -> Result<(&'a String, &'a String)> {
    match positionals {
        [consumer, item] => Ok((consumer, item)),
        _ => Err(crate::cli::args::Usage(usage.to_string()).into()),
    }
}

/// A save that lost to another writer, told by its type, not its sentence.
fn is_concurrent_change(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<crate::core::vault::VaultChangedConcurrently>()
        .is_some()
}
