// One name, one answer: the resolution every surface of this capability shares.
//
// The order is deliberate. A declaration is asked first, because it travels
// inside the item and survives a rename; the hand-declared table answers only
// what no item can declare. An ambiguous declaration is refused rather than
// falling through to the table, because two candidates mean the operator has
// not said which credential answers the name, and quietly serving the other
// source of truth is how the wrong credential reaches the right name.

use std::collections::HashMap;

use super::coordinate::coordinate;
use super::declaration::{
    agent_items, ambiguous, credential_field, login_targets, provider_items, Row, Target,
    AGENT_PREFIX, LOGIN_PREFIX, PROVIDER_PREFIX,
};
use crate::core::vault::Vault;
use anyhow::Result;
use serde_json::{Map, Value};

/// One item, a hash, one field: the coordinate the capability grammar writes.
const COORDINATE_SEPARATOR: char = '#';

/// Which coordinates one name resolves to, or the sentence that refuses it.
pub(super) fn targets(
    vault: &Vault,
    name: &str,
    table: &Map<String, Value>,
) -> Result<Vec<Target>, String> {
    if let Some(rest) = name.strip_prefix(PROVIDER_PREFIX) {
        let (provider, subscription) = match rest.split_once(':') {
            Some((provider, id)) => (provider, Some(id)),
            None => (rest, None),
        };
        let candidates: Vec<&str> = provider_items(vault)
            .into_iter()
            .filter(|(_, declared, id)| {
                *declared == provider && subscription_matches(*id, subscription)
            })
            .map(|(item, _, _)| item)
            .collect();
        match candidates[..] {
            [] => {}
            [item] => {
                let field = credential_field(vault, item)?;
                return Ok(vec![declared(item, &field, "tags")]);
            }
            _ => {
                return Err(format!(
                    "{} vault items declare {name}: {}",
                    candidates.len(),
                    candidates.join(", ")
                ))
            }
        }
    } else if let Some(agent) = name.strip_prefix(AGENT_PREFIX) {
        let candidates: Vec<String> = agent_items(vault, Some(agent))
            .into_iter()
            .map(|(_, item)| item)
            .collect();
        match candidates.as_slice() {
            [] => {}
            [item] => return Ok(vec![declared(item, "agent_auth_secret", "fields")]),
            _ => {
                return Err(format!(
                    "{} vault items declare {name}: {}",
                    candidates.len(),
                    candidates.join(", ")
                ))
            }
        }
    } else if let Some(item) = name.strip_prefix(LOGIN_PREFIX) {
        return login_targets(vault, item);
    } else if let Some((item, field)) = name.split_once(COORDINATE_SEPARATOR) {
        return Ok(vec![declared(item, field, "name")]);
    }
    let Some(entry) = table.get(name) else {
        return Err(format!(
            "nothing declares {name} and no capability route names it"
        ));
    };
    let (Some(item), Some(field)) = (
        entry.get("item").and_then(Value::as_str),
        entry.get("field").and_then(Value::as_str),
    ) else {
        return Err(format!(
            "capability route for {name} must name an item and a field"
        ));
    };
    Ok(vec![Target {
        item: item.to_string(),
        field: field.to_string(),
        exported: None,
        declared_by: "table",
        item_uid: entry
            .get("item_uid")
            .and_then(Value::as_str)
            .map(str::to_string),
    }])
}

/// A bare `provider:<provider>` names that provider's one credential, whatever
/// subscription it declares; `provider:<provider>:<id>` names exactly the one
/// declaring that id. Which credential answers the family is decided by there
/// being one, never by an id ending in `-primary` -- that suffix is a name an
/// operator may rewrite, and electing a default from it meant a rename silently
/// moved every request for the family onto a different credential.
fn subscription_matches(declared: Option<&str>, asked: Option<&str>) -> bool {
    match asked {
        None => true,
        Some(id) => declared == Some(id),
    }
}

fn declared(item: &str, field: &str, declared_by: &'static str) -> Target {
    Target {
        item: item.to_string(),
        field: field.to_string(),
        exported: None,
        declared_by,
        item_uid: None,
    }
}

/// Every name this vault answers without being asked for one: what the items
/// declare, plus every hand-declared row. A declared name appears whether or
/// not the table carries a row for it, which is the listing half of the same
/// defect -- a renamed item used to drop out of the listing while its stale row
/// stayed. `login:` names are resolved on request and never listed: every login
/// item in a vault would answer one.
pub(super) fn names(vault: &Vault, table: &Map<String, Value>) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for (_, provider, subscription) in provider_items(vault) {
        names.push(format!("{PROVIDER_PREFIX}{provider}"));
        if let Some(id) = subscription {
            names.push(format!("{PROVIDER_PREFIX}{provider}:{id}"));
        }
    }
    for (agent, _) in agent_items(vault, None) {
        names.push(format!("{AGENT_PREFIX}{agent}"));
    }
    names.extend(table.keys().cloned());
    names.sort();
    names.dedup();
    names
}

/// One name resolved, with the vault's answer for every coordinate it names.
///
/// A refusal is a row too, carrying the sentence and no coordinate, because a
/// caller asking for several names needs the one that failed named rather than
/// the whole answer replaced by an error.
pub(super) fn rows(
    vault: &Vault,
    table: &Map<String, Value>,
    names: &[String],
    opened: &mut HashMap<String, Result<Value, String>>,
) -> Vec<Row> {
    let mut rows = Vec::new();
    for name in names {
        match targets(vault, name, table) {
            Err(problem) => rows.push(Row {
                resource: name.clone(),
                item: String::new(),
                field: String::new(),
                exported: None,
                declared_by: "nothing",
                item_present: false,
                field_present: false,
                problem: Some(problem),
            }),
            Ok(targets) => {
                for target in targets {
                    let answer = coordinate(
                        vault,
                        opened,
                        &target.item,
                        &target.field,
                        target.item_uid.as_deref(),
                    );
                    rows.push(Row {
                        resource: name.clone(),
                        item: target.item,
                        field: target.field,
                        exported: target.exported,
                        declared_by: target.declared_by,
                        item_present: answer.item_present,
                        field_present: answer.field_present,
                        problem: answer.problem,
                    });
                }
            }
        }
    }
    rows
}

mod report;

pub(crate) use report::{coordinate_for, verdicts, verify_report};
pub(in crate::access) use report::rows_for;
pub(super) use report::walk;
