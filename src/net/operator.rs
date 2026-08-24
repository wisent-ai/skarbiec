// Operator routes of the loopback API: the surface a local operator console —
// the desktop app — reads and drives instead of launching the backend as a
// subprocess for every question it asks.
//
// Trust model: the listener is loopback-only, and every route here carries
// exactly the authority that invoking the backend binary on this machine
// already carries, because the local keyring decides what opens either way.
// What this surface deliberately does not carry is a value: get, export and
// resolve are absent, so a console reads metadata and refusals only. Grant
// minting answers without the bearer it created — the vault keeps only its
// digest, and the console reads the grant back from the grants route.
//
// Every handler delegates to the same dispatcher the matching command uses,
// so a console and an operator reading the same vault cannot drift. A request
// names its vault in the body's optional `vault` member; the request-scoped
// override in core applies it for exactly the thread answering here.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpStream;
use std::path::PathBuf;

use crate::core;
use crate::net::http;

const OK_LINE: &str = "HTTP/1.1 200 OK";
const BAD_LINE: &str = "HTTP/1.1 400 Bad Request";
const ROUTE_PREFIX: &str = "/v1/operator/";

/// The mutating operator routes, for the listener's write lock: a read stays
/// parallel, while a read-modify-write on the vault file never interleaves
/// with another writer. Credential calls are all here because a status read
/// can commit or roll back a staged revision.
pub(crate) fn is_mutation(path: &str) -> bool {
    matches!(
        path,
        "/v1/operator/vaults/create"
            | "/v1/operator/items/trash"
            | "/v1/operator/items/reclaim"
            | "/v1/operator/items/restore"
            | "/v1/operator/items/purge"
            | "/v1/operator/items/share"
            | "/v1/operator/items/revoke"
            | "/v1/operator/recipients/add"
            | "/v1/operator/grants/mint"
            | "/v1/operator/grants/revoke"
            | "/v1/operator/donations/accept"
            | "/v1/operator/donations/reject"
            | "/v1/operator/credential"
            | "/v1/operator/emergency/grant"
            | "/v1/operator/emergency/cancel"
            | "/v1/operator/emergency/activate"
            | "/v1/operator/recovery/drill"
            | "/v1/operator/policy/set"
            | "/v1/operator/sync/init"
            | "/v1/operator/sync/push"
            | "/v1/operator/sync/pull"
            | "/v1/operator/routes/add"
    )
}

/// Route one operator request; `false` when the path is not an operator
/// route, so the listener falls through to its own table.
pub(crate) fn handle(stream: &mut TcpStream, method: &str, path: &str, body: &str) -> Result<bool> {
    if !path.starts_with(ROUTE_PREFIX) {
        return Ok(false);
    }
    if method != "POST" {
        http::write_response(
            stream,
            BAD_LINE,
            &json!({"error": "operator routes are POST with a JSON body"}),
        )?;
        return Ok(true);
    }
    let parsed = http::request_json(body);
    let vault = parsed
        .get("vault")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let result = core::with_vault_override(vault, || answer(path, &parsed));
    match result {
        Ok(value) => http::write_response(stream, OK_LINE, &value)?,
        Err(error) => http::write_response(
            stream,
            BAD_LINE,
            &json!({"error": http::bounded_detail(&error.to_string())}),
        )?,
    }
    Ok(true)
}

fn answer(path: &str, parsed: &Value) -> Result<Value> {
    let none: Vec<String> = Vec::new();
    let no_flags = HashMap::new();
    match path {
        // Reads, each delegating to the dispatcher its command twin uses.
        "/v1/operator/items" => {
            crate::cmd_list(&HashMap::from([("all".to_string(), "true".to_string())]))
        }
        "/v1/operator/recipients" => access("users", &no_flags, &none),
        "/v1/operator/audit" => runtime("audit", &flags(parsed, &["limit"]), &none),
        "/v1/operator/audit-query" => runtime(
            "audit-query",
            &flags(
                parsed,
                &["op", "consumer", "item", "since", "until", "limit"],
            ),
            &none,
        ),
        "/v1/operator/chain" => runtime("verify-chain", &flags(parsed, &["tail"]), &none),
        "/v1/operator/policy" => access("policy-get", &no_flags, &none),
        "/v1/operator/grants" => access("tokens", &no_flags, &none),
        "/v1/operator/doctor" => crate::runtime::doctor::report(),
        "/v1/operator/status" => crate::core::items::status_json(),
        "/v1/operator/vaults" => crate::runtime::vaults::inventory(),
        "/v1/operator/donations" => inbox("donations", &no_flags, &none),
        "/v1/operator/emergency" => access("emergency-list", &no_flags, &none),
        "/v1/operator/recovery" => access("recovery-status", &no_flags, &none),
        "/v1/operator/key-doctor" => access("key-doctor", &no_flags, &none),
        "/v1/operator/bonds" => bonds("bonds", &no_flags, &none),
        "/v1/operator/version" => crate::cmd_version(),
        "/v1/operator/routes/list" => {
            let mut positionals = vec!["list".to_string()];
            if let Some(consumer) = optional(parsed, "consumer") {
                positionals.push(consumer);
            }
            access("routes", &no_flags, &positionals)
        }
        "/v1/operator/routes/verify" => {
            // The report is the answer, broken rows included: a console came
            // for exactly the routes a bare refusal would throw away.
            crate::access::routes::verify_report(optional(parsed, "consumer").as_deref())
        }
        // Mutations, one route per verb, bodies naming exact targets.
        "/v1/operator/vaults/create" => {
            crate::cmd_init(&no_flags, &positionals(parsed, &["owner"])?)
        }
        "/v1/operator/items/trash" => crate::cmd_delete(&positionals(parsed, &["id"])?),
        "/v1/operator/items/reclaim" => crate::cmd_reclaim(&positionals(parsed, &["id"])?),
        "/v1/operator/items/restore" => crate::cmd_restore(&positionals(parsed, &["id"])?),
        "/v1/operator/items/purge" => crate::cmd_purge(&positionals(parsed, &["id"])?),
        "/v1/operator/items/share" => {
            access("share", &no_flags, &positionals(parsed, &["id", "uid"])?)
        }
        "/v1/operator/items/revoke" => {
            access("revoke", &no_flags, &positionals(parsed, &["id", "uid"])?)
        }
        "/v1/operator/recipients/add" => access(
            "add-user",
            &flags(parsed, &["import", "role"]),
            &positionals(parsed, &["uid"])?,
        ),
        "/v1/operator/grants/mint" => {
            let mut report = access(
                "token-mint",
                &flags(
                    parsed,
                    &[
                        "capabilities",
                        "workload-public-key-file",
                        "ttl-seconds",
                        "audience",
                        "replace-capabilities",
                    ],
                ),
                &positionals(parsed, &["consumer"])?,
            )?;
            // The bearer this answer carries on the command path reaches no
            // console: the vault keeps only its digest, and the screen reads
            // the grant back from the grants route.
            if let Some(object) = report.as_object_mut() {
                object.remove("token");
            }
            Ok(report)
        }
        "/v1/operator/grants/revoke" => access(
            "token-revoke",
            &no_flags,
            &positionals(parsed, &["consumer"])?,
        ),
        "/v1/operator/donations/accept" => {
            inbox("donation-accept", &no_flags, &positionals(parsed, &["id"])?)
        }
        "/v1/operator/donations/reject" => {
            inbox("donation-reject", &no_flags, &positionals(parsed, &["id"])?)
        }
        "/v1/operator/credential" => {
            let operation = text(parsed, "operation")?;
            if !["status", "acquire", "rotate", "resume"].contains(&operation.as_str()) {
                bail!(
                    "operator credential operation must be one of status, acquire, rotate, resume"
                );
            }
            // Always this vault file: the console reports on and drives the
            // vault in view, never a canonical Skarbiec somewhere else.
            let mut call_flags = flags(parsed, &["provider", "consumer", "purpose", "account"]);
            call_flags.insert("local".to_string(), "true".to_string());
            credential(&call_flags, &[operation, text(parsed, "item")?])
        }
        "/v1/operator/emergency/grant" => access(
            "emergency-grant",
            &flags(parsed, &["activate-after"]),
            &positionals(parsed, &["grantee"])?,
        ),
        "/v1/operator/emergency/cancel" => access(
            "emergency-cancel",
            &no_flags,
            &positionals(parsed, &["grantee"])?,
        ),
        "/v1/operator/emergency/activate" => access(
            "emergency-activate",
            &no_flags,
            &positionals(parsed, &["grantee"])?,
        ),
        "/v1/operator/recovery/drill" => access(
            "recovery-drill",
            &no_flags,
            &positionals(parsed, &["subject"])?,
        ),
        "/v1/operator/policy/set" => access(
            "policy-set",
            &no_flags,
            &positionals(parsed, &["key", "value"])?,
        ),
        "/v1/operator/sync/init" => {
            net("sync-init", &no_flags, &positionals(parsed, &["endpoint"])?)
        }
        "/v1/operator/sync/push" => net("sync-push", &flags(parsed, &["message"]), &none),
        "/v1/operator/sync/pull" => net("sync-pull", &flags(parsed, &["force"]), &none),
        "/v1/operator/routes/add" => access(
            "routes",
            &flags(parsed, &["resource", "item", "field", "reason"]),
            &["add".to_string()],
        ),
        "/v1/operator/routes/reconcile" => access("routes", &no_flags, &["reconcile".to_string()]),
        _ => bail!("unknown operator route: {path}"),
    }
}

/// One dispatcher's answer, with the no-match case named: a route here always
/// stands for a real command, so `None` is a bug in this table, not an answer.
fn answered(result: Result<Option<Value>>) -> Result<Value> {
    result?.context("the backend produced no answer for an operator route")
}

fn access(command: &str, flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    answered(crate::access::dispatch(command, flags, positionals))
}

fn runtime(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    answered(crate::runtime::dispatch(command, flags, positionals))
}

fn net(command: &str, flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    answered(crate::net::dispatch(command, flags, positionals))
}

fn bonds(command: &str, flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    answered(crate::bonds::dispatch(command, flags, positionals))
}

fn inbox(command: &str, flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    answered(crate::core::inbox::dispatch(command, flags, positionals))
}

fn credential(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    answered(crate::credential::dispatch(
        "credential",
        flags,
        positionals,
        &core::vault_path(),
    ))
}

/// A required body member, named when absent so the console learns which of
/// its fields the route asked for.
fn text(parsed: &Value, key: &str) -> Result<String> {
    optional(parsed, key).with_context(|| format!("{key} required"))
}

fn optional(parsed: &Value, key: &str) -> Option<String> {
    parsed
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// The flags one dispatcher call gets, built from body members this route
/// named: a console can narrow a question, never smuggle a flag past the
/// route table. Strings pass through, numbers render, `true` sets a bare
/// flag — the shapes the flag parser already understands.
fn flags(parsed: &Value, keys: &[&str]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for key in keys {
        match parsed.get(*key) {
            Some(Value::String(value)) if !value.is_empty() => {
                out.insert((*key).to_string(), value.clone());
            }
            Some(Value::Bool(true)) => {
                out.insert((*key).to_string(), "true".to_string());
            }
            Some(value @ Value::Number(_)) => {
                out.insert((*key).to_string(), value.to_string());
            }
            _ => {}
        }
    }
    out
}

fn positionals(parsed: &Value, keys: &[&str]) -> Result<Vec<String>> {
    keys.iter().map(|key| text(parsed, key)).collect()
}
