// Declared route resolution: one capability answering which vault item and
// field a resource name resolves to.
//
// It replaces `routes list`, `routes add`, `routes reconcile`, `routes verify`,
// `resolve` and `expand`. Six verbs, because each was written for the incident
// that needed it: one to print the table, one to write a row, one to derive
// rows from the vault, one to check them, one to hand a login's fields to a
// consumer, one to fill a template. All six asked the same question -- which
// credential does this name reach -- and four of them answered it from a
// different source.
//
// Reconciliation is gone rather than renamed. It existed because resolution
// could not read a declaration: rows had to be derived from the vault ahead of
// time, and they went stale the moment an item was renamed, so `routes verify`
// reported a working credential as missing and reconciling again added
// nothing, because the resource was already in the table. Resolution now reads
// the declaration at the moment it is asked, and the table holds only what
// nothing declares.
//
// The three leaves: `resolve` answers what a name reaches and, with `--emit`
// or `--template`, materializes it; `declare` states the one row a vault item
// cannot express; `verify` confronts every resolvable route with the vault and
// exits non-zero when one cannot serve a usable credential.

use std::collections::HashMap;

use crate::core::schema::{exact_token, MAX_NAME_CHARS};
use crate::core::{vault::Vault, vault_path};
use declaration::{AGENT_PREFIX, LOGIN_PREFIX, PROVIDER_PREFIX};
use resolution as route_resolution;
use table::{self as route_table, MAX_REASON_CHARS, MAX_RESOURCE_CHARS};
use values as route_values;
pub mod coordinate;
pub mod declaration;
pub mod resolution;
pub mod table;
pub mod values;

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "route" {
        return Ok(None);
    }
    let subcommand = positionals.first().map(String::as_str).unwrap_or("help");
    let rest: Vec<String> = positionals.iter().skip(1).cloned().collect();
    let value = match subcommand {
        "resolve" => resolve(flags, &rest)?,
        "declare" => declare(flags)?,
        "verify" => verify(flags, &rest)?,
        "help" => help(),
        other => bail!("unknown route command: {other}"),
    };
    Ok(Some(value))
}

fn help() -> Value {
    json!({
        "commands": [
            "route resolve [<name>...] [--consumer <c> --token <t>] [--emit --out <dir>] [--template <file> --out <file>]",
            "route declare --resource <resource> --item <item> --field <field> --reason <text>",
            "route verify [<consumer>]",
        ],
        "names": [
            "provider:<provider> -- the one credential declaring brama:provider:<provider>",
            "provider:<provider>:<id> -- the credential also declaring brama:id:<id>",
            "agent:<agent> -- the internal-authority item whose id field names that agent",
            "login:<item> -- the fields that login item's kind declares, under their exported names",
            "<item>#<field> -- one exact coordinate, named rather than declared",
            "<resource> -- anything a vault item cannot declare, from the hand-declared table",
        ],
        "table": route_table::table_path().display().to_string(),
        "usage": "route resolve reads what the vault declares -- the brama:provider: and brama:id: tags an operator wrote on a credential, the id and agent_auth_secret fields an internal-authority item carries, and the fields a login's kind declares -- and never how an item happens to be named, so renaming an item does not change which credential a name reaches. A resource no item can declare, such as origin:<page origin>/<field class>, is stated once with route declare and answered by exact id, where a rename fails loudly in route verify and names where the item went. With no name, route resolve prints every route this vault answers plus every item whose declaration is too ambiguous to act on; --emit writes one owner-only <item>.env per item reached, and --template fills a caller's own file of skarbiec:// references. route verify exits non-zero when a route cannot serve a usable credential -- an item that is missing, renamed away, in the trash or will not open on this host, a field the item does not carry, and a field that is empty or contains an uppercase placeholder. The optional <consumer> argument matches resource text and is presentation only: it narrows what is printed and grants nothing, because redemption is authorised by the live grant that registers a workload's Ed25519 key, never by this surface.",
    })
}

/// Every name a caller may ask for is bounded exactly as `grant capability`
/// bounds a resource it will issue against: a name carrying a newline would
/// land in a report and in a journal line as something no later reader can
/// split back out.
fn exact_names(asked: &[String]) -> Result<Vec<String>> {
    for name in asked {
        if !exact_token(name, MAX_RESOURCE_CHARS) {
            bail!("route resolve requires exact names: {name} is not one");
        }
    }
    Ok(asked.to_vec())
}

/// What a name reaches, and -- when asked -- the values behind it.
///
/// The report is the same document in every mode, so a console rendering rows
/// and a provisioning sequence reading a file see one answer. A
/// materialization carries its own status beside it rather than replacing it.
fn resolve(flags: &HashMap<String, String>, asked: &[String]) -> Result<Value> {
    let names = exact_names(asked)?;
    let consumer = flags.get("consumer").map(String::as_str);
    let presented = match consumer {
        Some(_) => Some(
            flags
                .get("token")
                .map(String::as_str)
                .ok_or_else(|| anyhow!("--token required with --consumer"))?,
        ),
        None => None,
    };
    if let Some(template) = flags.get("template") {
        let out = route_values::require_out(flags, "template")?;
        return route_values::expand(template, &out);
    }
    // A listing narrows by consumer text; a named resolution answers exactly
    // the names asked, where the same filter could only remove one of them.
    let filter = if names.is_empty() { consumer } else { None };
    let (rows, mut document) = route_resolution::walk(&names, filter)?;
    if flags.get("emit").map(String::as_str) == Some("true") {
        let out = route_values::require_out(flags, "emit")?;
        let emitted = route_values::emit(&rows, &out, consumer, presented)?;
        if let Value::Object(fields) = &mut document {
            fields.insert("emitted".to_string(), emitted);
        }
    }
    // A name that reaches no coordinate at all is an error, not a status. The
    // predecessor answered `{"status": "blocked", "reason":
    // "no_stored_credential"}` and exited zero for a platform it had invented
    // an item id for, so a provisioning sequence carried on with no credential
    // and no signal. The document is still printed: the caller asked for
    // several names and needs to see which of them answered.
    let unresolved: Vec<String> = rows
        .iter()
        .filter(|row| !names.is_empty() && row.declared_by == "nothing")
        .filter_map(|row| row.problem.clone())
        .collect();
    if !unresolved.is_empty() {
        println!("{}", serde_json::to_string_pretty(&document)?);
        bail!("{}", unresolved.join("; "));
    }
    Ok(document)
}

/// A flag that is absent, empty, or carrying a newline is refused with the
/// validator the broker applies to a resource before it will issue a
/// capability for it.
fn required<'a>(flags: &'a HashMap<String, String>, name: &str, max: usize) -> Result<&'a str> {
    let value = flags.get(name).map(String::as_str).unwrap_or_default();
    if !exact_token(value, max) {
        bail!("route declare requires an exact --{name}");
    }
    Ok(value)
}

/// State one route the vault cannot declare for itself.
///
/// A name the vault already declares is refused rather than written: a hand
/// row beside a declaration is a second answer to one question, and the table
/// is the copy that goes stale. That refusal is the whole reason
/// reconciliation could be deleted instead of renamed.
fn declare(flags: &HashMap<String, String>) -> Result<Value> {
    let resource = required(flags, "resource", MAX_RESOURCE_CHARS)?;
    let item = required(flags, "item", MAX_NAME_CHARS)?;
    let field = required(flags, "field", MAX_NAME_CHARS)?;
    let reason = required(flags, "reason", MAX_REASON_CHARS)?;
    if declares_itself(resource) {
        bail!(
            "{resource} is resolved from what an item declares, not from the table: tag the item instead"
        );
    }
    // Opportunistic on purpose: a row may be declared ahead of provisioning,
    // so an unreadable vault leaves the row exactly as it would have been.
    let vault = Vault::open(vault_path()).ok();
    route_table::write_row(resource, item, field, reason, vault.as_ref())
}

/// Whether a name belongs to a vocabulary an item answers for itself: the
/// three prefixes resolution reads a declaration for, plus the exact
/// coordinate form, which needs no row either.
fn declares_itself(resource: &str) -> bool {
    resource.starts_with(PROVIDER_PREFIX)
        || resource.starts_with(AGENT_PREFIX)
        || resource.starts_with(LOGIN_PREFIX)
        || resource.contains('#')
}

/// Refuse a surface that cannot deliver what it promises.
///
/// The report goes to stdout even when the command fails, because both readers
/// matter: a console shows the rows, a provisioning sequence reads the exit
/// status. Nothing here restarts, deletes, or cycles anything -- it is safe
/// against a live broker.
fn verify(flags: &HashMap<String, String>, asked: &[String]) -> Result<Value> {
    let consumer = asked
        .first()
        .map(String::as_str)
        .or_else(|| flags.get("consumer").map(String::as_str));
    let report = route_resolution::verify_report(consumer)?;
    let broken = report
        .get("broken")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let checked = report
        .get("checked")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    if !broken.is_empty() {
        println!("{}", serde_json::to_string_pretty(&report)?);
        let named: Vec<String> = broken
            .iter()
            .map(|entry| {
                format!(
                    "{}: {}",
                    entry
                        .get("resource")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    entry
                        .get("problem")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                )
            })
            .collect();
        bail!(
            "{} of {} capability routes do not resolve: {}",
            broken.len(),
            checked,
            named.join("; ")
        );
    }
    Ok(report)
}
