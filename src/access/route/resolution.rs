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
use super::table as route_table;
use crate::core::{vault::Vault, vault_path};
use anyhow::Result;
use serde_json::{json, Map, Value};

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

/// Presentation only. The consumer argument narrows what is printed and
/// authorises nothing: a resource absent from a listing is refused because
/// nothing resolves it, and a resource present in one is redeemed only by a
/// workload whose key a live grant registers.
fn selected(names: Vec<String>, consumer: Option<&str>) -> Vec<String> {
    names
        .into_iter()
        .filter(|name| consumer.is_none_or(|needle| name.contains(needle)))
        .collect()
}

/// One walk of the surface, shared by every reader: with no names asked it
/// walks everything this vault resolves and reports the items whose
/// declaration cannot be acted on beside it; with names, exactly those, in the
/// order asked.
pub(super) fn walk(asked: &[String], consumer: Option<&str>) -> Result<(Vec<Row>, Value)> {
    let vault = Vault::open(vault_path())?;
    let table = route_table::load()?;
    let whole = asked.is_empty();
    let names = if whole {
        selected(names(&vault, &table), consumer)
    } else {
        asked.to_vec()
    };
    let mut opened = HashMap::new();
    let rows = rows(&vault, &table, &names, &mut opened);
    let mut document = Map::new();
    document.insert("consumer".to_string(), json!(consumer));
    document.insert(
        "table".to_string(),
        json!(route_table::table_path().display().to_string()),
    );
    document.insert(
        "routes".to_string(),
        json!(rows.iter().map(Row::as_json).collect::<Vec<Value>>()),
    );
    if whole {
        document.insert("undeclared".to_string(), json!(ambiguous(&vault)));
        document.insert(
            "shadowed_rows".to_string(),
            json!(route_table::shadowed(&table, &rows)),
        );
    }
    Ok((rows, Value::Object(document)))
}

/// Every route this host resolves, with the vault's answer beside it.
pub(crate) fn verdicts(consumer: Option<&str>) -> Result<Vec<Row>> {
    Ok(walk(&[], consumer)?.0)
}

/// One name, resolved for a caller that cannot print a document: the loopback
/// route and the template both need the coordinates and not the report.
pub(super) fn rows_for(
    vault: &Vault,
    table: &Map<String, Value>,
    name: &str,
) -> Result<Vec<Row>, String> {
    targets(vault, name, table)?;
    let mut opened = HashMap::new();
    Ok(rows(vault, table, &[name.to_string()], &mut opened))
}

/// The verification report, always returned: which routes were checked and
/// which refuse, in the backend's own words. The command turns a non-empty
/// `broken` into a non-zero exit after printing it; the loopback operator API
/// answers with it, because a console came for exactly those rows.
pub(crate) fn verify_report(consumer: Option<&str>) -> Result<Value> {
    let rows = verdicts(consumer)?;
    Ok(json!({
        "checked": rows.len(),
        "broken": rows
            .iter()
            .filter_map(|row| row.problem.as_ref().map(|problem| {
                json!({"resource": row.resource, "problem": problem})
            }))
            .collect::<Vec<Value>>(),
    }))
}

/// The one coordinate `grant capability` issues against.
///
/// It asks the same resolution every other surface asks, so a capability is
/// issued for exactly the credential a redemption will reach -- including a
/// provider whose item was renamed after the grant was written, which used to
/// be issued against a stale row and refused at the far end.
///
/// The inner result is the refusal's own sentence rather than a bare absence:
/// "nothing declares this" and "two items declare this" are different repairs,
/// and the refusal a gateway records is the only place either is visible.
pub(crate) fn coordinate_for(resource: &str) -> Result<Result<(String, String), String>> {
    let vault = Vault::open(vault_path())?;
    let table = route_table::load()?;
    match targets(&vault, resource, &table) {
        Ok(targets) => Ok(targets
            .into_iter()
            .next()
            .map(|target| (target.item, target.field))
            .ok_or_else(|| {
                format!("nothing declares {resource} and no capability route names it")
            })),
        Err(problem) => Ok(Err(problem)),
    }
}
