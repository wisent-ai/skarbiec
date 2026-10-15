// Declared route resolution: one capability answering which vault item and
// field a resource name resolves to.
//
// Resolution reads the item's current declaration rather than a derived copy
// that can become stale after a rename. The explicit table holds only routes
// that no vault item declares.
//
// The three leaves: `resolve` answers what a name reaches and, with `--emit`
// or `--template`, materializes it; `declare` states the one row a vault item
// cannot express; `verify` confronts every resolvable route with the vault and
// exits non-zero when one cannot serve a usable credential.

use std::collections::HashMap;

use crate::core::schema::exact_token;
use crate::core::{vault::Vault, vault_path};
use declaration::{AGENT_PREFIX, LOGIN_PREFIX, PROVIDER_PREFIX};
use resolution as route_resolution;
use table as route_table;
use values as route_values;
pub mod coordinate;
pub mod declaration;
pub mod resolution;
mod syntax;
use syntax::{exact_names, help};
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
    // A bare `route` prints its help.
    let (subcommand, rest) = match positionals.split_first() {
        Some((subcommand, rest)) => (subcommand.as_str(), rest),
        None => ("help", positionals),
    };
    let value = match subcommand {
        "resolve" => resolve(flags, rest)?,
        "declare" => declare(flags)?,
        "withdraw" => withdraw(flags)?,
        "verify" => verify(flags, rest)?,
        "help" => help(),
        other => {
            return Err(crate::cli::args::Usage(format!(
                "unknown route command: {other}; `skarbiec route help` lists them"
            ))
            .into())
        }
    };
    Ok(Some(value))
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
        Some(_)
            if flags.get("emit").map(String::as_str) == Some("true")
                || flags.contains_key("template") =>
        {
            Some(
                flags
                    .get("token")
                    .map(String::as_str)
                    .ok_or_else(|| anyhow!("--token required with --consumer"))?,
            )
        }
        _ => None,
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
fn required<'a>(flags: &'a HashMap<String, String>, name: &str) -> Result<&'a str> {
    match flags.get(name) {
        Some(value) if exact_token(value) => Ok(value),
        _ => Err(crate::cli::args::Usage(format!(
            "route: --{name} is required and must be exact (non-empty, one line)"
        ))
        .into()),
    }
}

/// State one route the vault cannot declare for itself.
///
/// A name the vault already declares is refused rather than written: a hand
/// row beside a declaration is a second answer to one question, and the table
/// is the copy that goes stale. That refusal is the whole reason
/// reconciliation could be deleted instead of renamed. A row names either the
/// item (`--item`) or the tag the one answering item carries (`--tag`); a
/// tagged row survives any rename and names nothing an operator chose.
fn declare(flags: &HashMap<String, String>) -> Result<Value> {
    let resource = required(flags, "resource")?;
    let (key, value) = match (flags.contains_key("item"), flags.contains_key("tag")) {
        (true, false) => ("item", required(flags, "item")?),
        (false, true) => ("tag", required(flags, "tag")?),
        _ => {
            return Err(crate::cli::args::Usage(
                "route declare takes exactly one of --item or --tag".to_string(),
            )
            .into())
        }
    };
    let field = required(flags, "field")?;
    let reason = required(flags, "reason")?;
    if declares_itself(resource) {
        bail!(
            "{resource} is resolved from what an item declares, not from the table: tag the item instead"
        );
    }
    // A row may be declared ahead of provisioning, so a host with no vault
    // yet writes the row unchecked. A vault that is there and does not open
    // is the error, with its cause, rather than a row written as if it were
    // absent.
    let path = vault_path();
    let mut vault = match crate::core::is_present(&path, "vault")? {
        true => Some(Vault::open(path)?),
        false => None,
    };
    if key == "tag" {
        if let Some(open) = vault.as_mut() {
            adopt_live_item(open, resource, value, field, reason)?;
        }
    }
    route_table::write_row(resource, key, value, field, reason, vault.as_ref())
}

/// A tag row declared over a live item row, for a role no item carries yet:
/// the item the route already answers with is the role's only evident
/// holder, so it is tagged with the role here, in the same step, and the tag
/// row then names that very item without repointing the route. Without this
/// every consumer moving its routes from items to roles stopped at the first
/// unheld role until someone tagged the item by hand. A role another item
/// already carries is left to `write_row`, which refuses the repoint.
fn adopt_live_item(
    vault: &mut Vault,
    resource: &str,
    tag: &str,
    field: &str,
    reason: &str,
) -> Result<()> {
    let table = route_table::load()?;
    let Some(row) = table.get(resource) else {
        return Ok(());
    };
    // A row naming no item, or another field, is not the route this tag row
    // replaces; and a role some item already carries needs no adoption.
    let (Some(item), Some(row_field)) = (
        row.get("item").and_then(Value::as_str),
        row.get("field").and_then(Value::as_str),
    ) else {
        return Ok(());
    };
    let item = item.to_string();
    if row_field != field || !declaration::tagged_items(vault, tag).is_empty() {
        return Ok(());
    }
    let Some(record) = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(&item))
        .cloned()
    else {
        return Ok(());
    };
    crate::cli::items::ensure_owner_mutation_allowed(vault, &item, "route role adoption")?;
    let mut tags = crate::core::vault::entry_texts(&item, &record, "tags")?;
    tags.push(tag.to_string());
    vault.set_item_tags(&item, &tags)?;
    crate::runtime::audit::append_sync(
        "capability-route-role-adopted",
        &serde_json::json!({
            "resource": resource,
            "item": item,
            "tag": tag,
            "field": field,
            "reason": reason,
        }),
    )?;
    Ok(())
}

/// Withdraw one row `declare` wrote. The reason is required for the same
/// reason a declaration's is: this table decides which credential a login form
/// receives, so its history must say why a route stopped answering.
fn withdraw(flags: &HashMap<String, String>) -> Result<Value> {
    let resource = required(flags, "resource")?;
    let reason = required(flags, "reason")?;
    route_table::remove_row(resource, reason)
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
    let (Some(broken), Some(checked)) = (
        report.get("broken").and_then(Value::as_array),
        report.get("checked").and_then(Value::as_u64),
    ) else {
        bail!("the route verification report lacks its broken list or checked count: {report}");
    };
    if !broken.is_empty() {
        println!("{}", serde_json::to_string_pretty(&report)?);
        let named: Vec<String> = broken
            .iter()
            .map(|entry| {
                match (
                    entry.get("resource").and_then(Value::as_str),
                    entry.get("problem").and_then(Value::as_str),
                ) {
                    (Some(resource), Some(problem)) => format!("{resource}: {problem}"),
                    // A row that does not say its resource and problem is
                    // shown whole rather than as an empty sentence.
                    _ => entry.to_string(),
                }
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
