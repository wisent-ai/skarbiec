// Runtime credential resolution + reference expansion (like `op run` / `bws run`).
//   resolve: gate by consumer capability, decrypt one item, optionally write a
//     mode-0600 shell file of ADMIN_* variables (names returned; values only in file).
//   expand: replace `NAME=skarbiec://<id>/<field>` lines with decrypted values.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;

use crate::access::tokens;
use crate::core::{schema, vault::Vault, vault_path};
use crate::net::http;

fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

// (logical field, exported name). Storage has no legacy aliases.
fn name_table() -> Vec<(&'static str, &'static str)> {
    vec![
        ("username", "ADMIN_EMAIL"),
        ("password", "ADMIN_PASSWORD"),
        ("totp_secret", "ADMIN_TOTP"),
    ]
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn chmod_600(path: &PathBuf) {
    Command::new("chmod").arg("600").arg(path).status().ok();
}

// Canonical exported mapping from one validated login payload.
fn mapping_for(payload: &Value) -> Vec<(String, String)> {
    name_table()
        .into_iter()
        .filter_map(|(field, name)| {
            schema::field(payload, field)
                .ok()
                .and_then(Value::as_str)
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect()
}

fn normalize_id(vault: &Vault, target: &str) -> String {
    let known = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .map(|m| m.contains_key(target))
        .unwrap_or(false);
    if known {
        target.to_string()
    } else {
        format!("platform-admin-{target}")
    }
}

fn login_mapping(payload: &Value) -> Vec<(String, String)> {
    mapping_for(payload)
}

// HTTP `POST /resolve` handler, routed by net::http's listener. It lives here
// — next to the CLI resolve it mirrors — because net::http is at the
// repository's per-file line budget. Behavior is unchanged from when it was
// inline in the router.
pub fn handle_http_resolve(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let parsed = http::request_json(body);
    let platform = parsed.get("platform").and_then(Value::as_str).unwrap_or("");
    if platform.is_empty() {
        return http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": "platform required"}),
        );
    }
    let (consumer, bearer) = http::presented_identity(headers);
    let vault = load()?;
    let id = normalize_id(&vault, platform);
    let payload = vault.get_item(&id)?;
    let mapping: HashMap<String, String> = login_mapping(&payload)
        .into_iter()
        .filter(|(name, _)| {
            let field = name_table()
                .into_iter()
                .find_map(|(field, exported)| (exported == name).then_some(field));
            field.is_some_and(|field| {
                tokens::token_allows_field_action(&vault, &consumer, &bearer, "read", &id, field)
                    .unwrap_or(false)
            })
        })
        .collect();
    if consumer.is_empty() || mapping.is_empty() {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "consumer has no authorized login fields"}),
        );
    }
    crate::runtime::audit::append(
        "http-resolve",
        &json!({"item": id, "consumer": consumer, "names": mapping.keys().collect::<Vec<_>>()}),
    )?;
    http::write_response(stream, "HTTP/1.1 200 OK", &json!(mapping))
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "resolve" => {
            let target = positionals
                .first()
                .context("usage: resolve <platform> [--consumer c --token t] [--emit --out dir]")?;
            let vault = load()?;
            let id = normalize_id(&vault, target);
            let consumer = flags.get("consumer");
            let presented = consumer
                .map(|_| {
                    flags
                        .get("token")
                        .context("--token required with --consumer")
                })
                .transpose()?;
            let known = vault
                .doc()
                .get("items")
                .and_then(Value::as_object)
                .map(|m| m.contains_key(&id))
                .unwrap_or(false);
            if !known {
                return Ok(Some(
                    json!({"status": "blocked", "platform": id, "reason": "no_stored_credential"}),
                ));
            }
            let payload = vault.get_item(&id)?;
            let mapping: Vec<(String, String)> = mapping_for(&payload)
                .into_iter()
                .filter(|(name, _)| {
                    let Some(consumer) = consumer else {
                        return true;
                    };
                    let field = name_table()
                        .into_iter()
                        .find_map(|(field, exported)| (exported == name).then_some(field));
                    field.is_some_and(|field| {
                        tokens::token_allows_field_action(
                            &vault,
                            consumer,
                            presented.expect("presented token required"),
                            "read",
                            &id,
                            field,
                        )
                        .unwrap_or(false)
                    })
                })
                .collect();
            if consumer.is_some() && mapping.is_empty() {
                return Ok(Some(json!({
                    "status": "blocked",
                    "platform": id,
                    "consumer": consumer,
                    "reason": "token_denies_all_fields",
                })));
            }
            let names: Vec<String> = mapping.iter().map(|(name, _)| name.clone()).collect();
            if flags.get("emit").map(|v| v == "true").unwrap_or(false) {
                let dir = PathBuf::from(
                    flags
                        .get("out")
                        .map(String::as_str)
                        .unwrap_or(".vault-resolved"),
                );
                std::fs::create_dir_all(&dir)?;
                let out_file = dir.join(format!("{id}.env"));
                let body = mapping
                    .iter()
                    .map(|(name, value)| format!("{name}={}", shell_quote(value)))
                    .collect::<Vec<_>>()
                    .join("\n");
                std::fs::write(&out_file, format!("{body}\n"))?;
                chmod_600(&out_file);
                crate::runtime::audit::append(
                    "resolve",
                    &json!({"item": id, "consumer": consumer, "names": names}),
                )?;
                return Ok(Some(
                    json!({"status": "ready", "platform": id, "out_file": out_file.display().to_string(), "names": names}),
                ));
            }
            let context = schema::field(&payload, "context")
                .ok()
                .and_then(Value::as_object);
            Ok(Some(json!({
                "status": "ready",
                "platform": id,
                "names": names,
                "login_method": context.and_then(|value| value.get("provider")),
            })))
        }
        "expand" => {
            let template = positionals
                .first()
                .context("usage: expand <template> --out <file>")?;
            let out = flags.get("out").context("--out <file> required")?;
            let body =
                std::fs::read_to_string(template).with_context(|| format!("read {template}"))?;
            let vault = load()?;
            let mut result = String::new();
            for line in body.lines() {
                match line.split_once("=skarbiec://") {
                    Some((name, reference)) => {
                        let (id, field) = reference
                            .rsplit_once('/')
                            .context("reference must be skarbiec://<id>/<field>")?;
                        let payload = vault.get_item(id)?;
                        let value = schema::field(&payload, field)
                            .with_context(|| format!("{id} has no canonical field {field}"))?
                            .as_str()
                            .with_context(|| format!("{id}#{field} is not text"))?;
                        result.push_str(&format!("{name}={}\n", shell_quote(value)));
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
            crate::runtime::audit::append("expand", &json!({"template": template, "out": out}))?;
            Ok(Some(json!({"status": "ready", "out_file": out})))
        }
        _ => Ok(None),
    }
}
