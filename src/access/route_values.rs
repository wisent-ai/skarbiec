// Materializing what a resolved route names: the value half of declared route
// resolution.
//
// Resolution answers which item and field a name reaches; this writes those
// values where a consumer can use them -- a mode-0600 environment file, or a
// caller's own template of references. Nothing here decides which credential a
// name means: that is the declaration's job, asked exactly once, in
// `route_resolution`.
//
// A value never reaches stdout, an argument list or a log line. The answer
// names variables and files; the file is written owner-only.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;

use super::route_declaration::Row;
use super::route_resolution::{rows_for, targets};
use super::{grant, route_table};
use crate::core::{schema, vault::Vault, vault_path};
use crate::net::http;

// (declared field, exported variable). A login states which of these it
// carries; the exported name is this product's canonical vocabulary for it, so
// a trajectory reading `ADMIN_PASSWORD` never has to know the item's id.
const LOGIN_FIELDS: &[(&str, &str)] = &[
    ("username", "ADMIN_EMAIL"),
    ("password", "ADMIN_PASSWORD"),
    ("totp_secret", "ADMIN_TOTP"),
];

pub(super) fn login_fields() -> &'static [(&'static str, &'static str)] {
    LOGIN_FIELDS
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn chmod_600(path: &PathBuf) {
    Command::new("chmod").arg("600").arg(path).status().ok();
}

/// The variable one resolved coordinate is exported under: the login kind's
/// canonical name when it declares one, and otherwise the field's own name in
/// the shape an environment accepts.
fn exported(row: &Row) -> String {
    row.exported.map(str::to_string).unwrap_or_else(|| {
        row.field
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect()
    })
}

/// Whether a named consumer may read this exact coordinate.
///
/// An unnamed consumer is the owner running the command against their own
/// vault, which the recipient group already decides. A named one presents a
/// grant, and an unconfirmed adopt candidate stays invisible to every consumer
/// read whatever that grant says.
fn readable(
    vault: &Vault,
    consumer: Option<&str>,
    presented: Option<&str>,
    item: &str,
    field: &str,
) -> bool {
    let Some(consumer) = consumer else {
        return true;
    };
    grant::token_allows_field_action(
        vault,
        consumer,
        presented.unwrap_or_default(),
        "read",
        item,
        field,
    )
    .unwrap_or(false)
        && !crate::credential::candidate_hidden(vault, item, field, consumer)
}

/// The values behind resolved rows, as (item, variable, value).
fn values(
    vault: &Vault,
    rows: &[Row],
    consumer: Option<&str>,
    presented: Option<&str>,
) -> Vec<(String, String, String)> {
    rows.iter()
        .filter(|row| row.field_present)
        .filter(|row| readable(vault, consumer, presented, &row.item, &row.field))
        .filter_map(|row| {
            let payload = vault.get_item(&row.item).ok()?;
            let value = schema::field(&payload, &row.field)
                .ok()
                .and_then(Value::as_str)?;
            Some((row.item.clone(), exported(row), value.to_string()))
        })
        .collect()
}

/// Write one owner-only environment file per item a resolution reached.
///
/// The names are returned and the values are not: the answer a caller reads
/// and the file a caller sources are deliberately different documents.
pub(super) fn emit(
    rows: &[Row],
    directory: &str,
    consumer: Option<&str>,
    presented: Option<&str>,
) -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    let resolved = values(&vault, rows, consumer, presented);
    if resolved.is_empty() {
        return Ok(json!({
            "status": "blocked",
            "consumer": consumer,
            "reason": "no resolved coordinate is readable by this caller",
        }));
    }
    let directory = PathBuf::from(directory);
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("create {}", directory.display()))?;
    let mut bodies: Vec<(String, String)> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for (item, name, value) in &resolved {
        let line = format!("{name}={}\n", shell_quote(value));
        match bodies.iter_mut().find(|(known, _)| known == item) {
            Some((_, body)) => body.push_str(&line),
            None => bodies.push((item.clone(), line)),
        }
        names.push(name.clone());
    }
    let mut files: Vec<Value> = Vec::new();
    for (item, body) in &bodies {
        let path = directory.join(format!("{item}.env"));
        std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
        chmod_600(&path);
        files.push(json!({"item": item, "out_file": path.display().to_string()}));
    }
    names.sort();
    names.dedup();
    crate::runtime::audit::append(
        "route-resolve-emit",
        &json!({"consumer": consumer, "names": names}),
    )?;
    Ok(json!({"status": "ready", "files": files, "names": names}))
}

/// One reference inside a template, resolved through the same grammar the
/// command resolves a name with.
///
/// `skarbiec://<item>/<field>` is an exact coordinate and stays exactly that;
/// `skarbiec://provider:openai` now reaches the same credential the broker
/// does, so a template no longer has to name an item whose id may change.
fn reference(vault: &Vault, table: &Map<String, Value>, asked: &str) -> Result<(String, String)> {
    if let Ok(resolved) = targets(vault, asked, table) {
        if let Some(target) = resolved.into_iter().next() {
            return Ok((target.item, target.field));
        }
    }
    let (item, field) = asked.rsplit_once('/').with_context(|| {
        format!("reference must be skarbiec://<item>/<field> or a resolvable name, not {asked}")
    })?;
    let resolved = targets(vault, &format!("{item}#{field}"), table)
        .map_err(anyhow::Error::msg)?
        .into_iter()
        .next()
        .with_context(|| format!("nothing resolves {asked}"))?;
    Ok((resolved.item, resolved.field))
}

/// Replace every `NAME=skarbiec://<reference>` line with the value behind it,
/// leaving every other line as it stands.
pub(super) fn expand(template: &str, out: &str) -> Result<Value> {
    let body = std::fs::read_to_string(template).with_context(|| format!("read {template}"))?;
    let vault = Vault::open(vault_path())?;
    let table = route_table::load()?;
    let mut result = String::new();
    let mut names: Vec<String> = Vec::new();
    for line in body.lines() {
        match line.split_once("=skarbiec://") {
            Some((name, asked)) => {
                let (item, field) = reference(&vault, &table, asked)?;
                let payload = vault.get_item(&item)?;
                let value = schema::field(&payload, &field)
                    .with_context(|| format!("{item} has no canonical field {field}"))?
                    .as_str()
                    .with_context(|| format!("{item}#{field} is not text"))?;
                result.push_str(&format!("{name}={}\n", shell_quote(value)));
                names.push(name.to_string());
            }
            None => {
                result.push_str(line);
                result.push('\n');
            }
        }
    }
    let out_path = PathBuf::from(out);
    std::fs::write(&out_path, result)?;
    chmod_600(&out_path);
    crate::runtime::audit::append(
        "route-resolve-template",
        &json!({"template": template, "out": out, "names": names}),
    )?;
    Ok(json!({"status": "ready", "out_file": out, "names": names}))
}

/// `POST /v1/route/resolve`: the loopback twin of `route resolve`, for a
/// consumer that holds a grant and cannot run a command.
///
/// It answers variables and values for one name, and it lives here -- next to
/// the materialization it performs -- because `net::http` is at this
/// repository's per-file line budget.
pub(crate) fn handle_http_resolve(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let parsed = http::request_json(body);
    let name = parsed.get("name").and_then(Value::as_str).unwrap_or("");
    if name.is_empty() {
        return http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": "name required"}),
        );
    }
    let (consumer, bearer) = http::presented_identity(headers);
    let vault = Vault::open(vault_path())?;
    let table = route_table::load()?;
    let rows = match rows_for(&vault, &table, name) {
        Ok(rows) => rows,
        Err(problem) => {
            return http::write_response(
                stream,
                "HTTP/1.1 404 Not Found",
                &json!({"error": problem}),
            )
        }
    };
    let mapping: HashMap<String, String> = values(&vault, &rows, Some(&consumer), Some(&bearer))
        .into_iter()
        .map(|(_, variable, value)| (variable, value))
        .collect();
    if consumer.is_empty() || mapping.is_empty() {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "consumer has no authorized field on this route"}),
        );
    }
    crate::runtime::audit::append(
        "http-route-resolve",
        &json!({"resource": name, "consumer": consumer, "names": mapping.keys().collect::<Vec<_>>()}),
    )?;
    http::write_response(stream, "HTTP/1.1 200 OK", &json!(mapping))
}

/// Refuse a materialization the caller did not fully state, before anything is
/// opened or written.
pub(super) fn require_out(flags: &HashMap<String, String>, what: &str) -> Result<String> {
    match flags.get("out").map(String::as_str).unwrap_or_default() {
        "" => bail!("route resolve --{what} requires --out"),
        out => Ok(out.to_string()),
    }
}
