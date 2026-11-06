use crate::cli::args::OrUsage;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;

mod commands;
mod config;
pub(crate) use commands::local;
use commands::{SEED_LEAF, TOTP};
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
                super::serve::serve_request(&endpoint, "POST", path, "", "", Some(&body))
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

/// Run `command` on the vault owner when Stado routes this machine to one:
/// every command another product runs against the fleet's vault, so a product
/// that runs the CLI stands on any host, not only on the one holding the
/// vault file. `Ok(false)` when this machine serves the command itself (no
/// owner route, or a command that does not read the fleet's vault).
pub(crate) fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<bool> {
    let capability =
        command == "grant" && positionals.first().map(String::as_str) == Some(CAPABILITY_LEAF);
    let pick = crate::cli::args::verb(command, positionals, LOGIN, PICK_LEAF);
    let seed = crate::cli::args::verb(command, positionals, TOTP, SEED_LEAF);
    // The owner route each forwarded command runs as; every other command is
    // this machine's to serve.
    let path = match command {
        _ if pick.is_some() => "/v1/operator/items/site-get",
        _ if seed.is_some() => "/v1/operator/totp/seed-state",
        _ if capability => "/v1/operator/grants/capability",
        "get" => "/v1/operator/items/get",
        "list" => "/v1/operator/items/list",
        "set" => "/v1/operator/items/set-json",
        "status" => "/v1/operator/status",
        // The owner's trash route is the command line's `delete`.
        "delete" => "/v1/operator/items/trash",
        "retag" => "/v1/operator/items/retag",
        _ => return Ok(false),
    };
    let Some(route) = selected()? else {
        return Ok(false);
    };
    let mut body = json!({"flags": flags, "positionals": positionals});
    if let Some(rest) = pick {
        // A product that signs in somewhere asks by site from any host.
        body = json!({
            "site": rest.first().or_usage(SITE_GET_USAGE)?,
            "field": flags.get("field"),
            "username": flags.get("username"),
        });
    } else if let Some(rest) = seed {
        body = json!({"flags": flags, "positionals": rest});
    } else if capability {
        // The owner's capability route reads each flag from a body member of
        // its name, as `grant capability` reads its flags.
        body = Value::Object(
            flags
                .iter()
                .map(|(name, value)| (name.clone(), Value::String(value.clone())))
                .collect(),
        );
    } else if command == "get" {
        positionals.first().or_usage(crate::cli::reads::GET_USAGE)?;
    } else if command == "set" {
        positionals
            .first()
            .or_usage(crate::cli::items::SET_JSON_USAGE)?;
        let mut encoded = String::new();
        std::io::stdin().read_to_string(&mut encoded)?;
        body["payload"] = Value::String(encoded);
    } else if command == "delete" {
        // The item from `id`, the tag from `tag` for `delete --tag`, or the
        // moment from `untouched-since`, with yes for either.
        let yes = crate::cli::args::flag_set(flags, "yes");
        body = match (flags.get("tag"), flags.get("untouched-since")) {
            (Some(tag), _) => json!({"tag": tag, "yes": yes}),
            (None, Some(moment)) => json!({"untouched-since": moment, "yes": yes}),
            (None, None) => json!({"id": positionals.first().or_usage(DELETE_USAGE)?}),
        };
    }
    let answer = request(&route, path, &body)?;
    if command == "get" {
        crate::cli::reads::emit_get(flags, &answer)?;
    } else {
        crate::cli::args::emit(&answer)?;
    }
    Ok(true)
}

/// `grant capability`: the leaf of `grant` that issues one capability.
const CAPABILITY_LEAF: &str = "capability";

/// What `delete` takes, said when a forwarded one names no item.
const DELETE_USAGE: &str =
    "usage: delete <id> | delete --tag <tag> [--yes] | delete --untouched-since <iso8601> [--yes]";

/// `login get`: the noun and the leaf that pick a login by site.
const LOGIN: &str = "login";
const PICK_LEAF: &str = "get";

/// What `login get` takes, said when a forwarded one names no site.
const SITE_GET_USAGE: &str =
    "usage: login get <host or address> --field <field|one-time-code> [--username <name>]";
