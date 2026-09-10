// Walking every route this host resolves and reporting what the vault
// answers for each one, including the names it refuses and why.

use anyhow::Result;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::core::{vault::Vault, vault_path};

use super::super::table as route_table;
use super::{ambiguous, names, rows, targets, Row};

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
pub(in crate::access) fn walk(
    asked: &[String],
    consumer: Option<&str>,
) -> Result<(Vec<Row>, Value)> {
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
pub(in crate::access) fn rows_for(
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
