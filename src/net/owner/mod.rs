use crate::cli::args::OrUsage;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;

mod commands;
mod config;
pub(crate) use commands::local;
pub(crate) use config::selected;

/// The member an owner request carries, so the owner serves it from its own
/// vault and never forwards it again.
pub(crate) const FORWARDED: &str = "forwardedToOwner";

pub(crate) fn request(route: &str, path: &str, body: &Value) -> Result<Value> {
    let endpoint = config::resolve(route)?;
    let mut body = body.clone();
    body.as_object_mut()
        .context("owner request body is not a JSON object")?
        .insert(FORWARDED.into(), Value::Bool(true));
    let value = stado_wait::blocking(
        stado_wait::Kind::Network,
        format!("Skarbiec owner POST {path}"),
        &endpoint,
        || -> std::io::Result<Value> {
            let (status, value) =
                super::bond::serve_request(&endpoint, "POST", path, "", "", Some(&body))
                    .map_err(std::io::Error::other)?;
            if status != super::operator::OK_LINE {
                return Err(std::io::Error::other(format!(
                    "vault owner {route} at {endpoint} refused {path}: {status}: {value}"
                )));
            }
            Ok(value)
        },
    )
    .with_context(|| format!("request vault owner {route} at {endpoint}: {path}"))?;
    if path == "/v1/operator/status" {
        let mut value = value;
        let object = value
            .as_object_mut()
            .context("owner status response is not an object")?;
        object.insert(
            "source".into(),
            json!({"kind":"remote", "route":route, "endpoint":endpoint}),
        );
        return Ok(value);
    }
    Ok(value)
}

pub(crate) fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<bool> {
    if !matches!(command, "get" | "list" | "set-json" | "status") {
        return Ok(false);
    }
    let Some(route) = selected()? else {
        return Ok(false);
    };
    let mut body = json!({"flags": flags, "positionals": positionals});
    let path = match command {
        "get" => {
            positionals.first().or_usage(crate::cli::reads::GET_USAGE)?;
            "/v1/operator/items/get"
        }
        "list" => "/v1/operator/items/list",
        "set-json" => {
            positionals
                .first()
                .or_usage(crate::cli::items::SET_JSON_USAGE)?;
            let mut encoded = String::new();
            std::io::stdin().read_to_string(&mut encoded)?;
            body["payload"] = Value::String(encoded);
            "/v1/operator/items/set-json"
        }
        "status" => "/v1/operator/status",
        _ => unreachable!(),
    };
    let answer = request(&route, path, &body)?;
    if command == "get" {
        crate::cli::reads::emit_get(flags, &answer)?;
    } else {
        crate::cli::args::emit(&answer)?;
    }
    Ok(true)
}
