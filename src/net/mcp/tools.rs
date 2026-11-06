// The tools an agent may call over MCP, and the configuration each of them
// needs. Raw item reads, minting and rotation are deliberately absent.

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::core::vault::Vault;
use crate::core::vault_path;
use crate::runtime;
use std::collections::HashMap;

pub(super) fn schema(properties: Value, required: Vec<&str>) -> Value {
    json!({"type": "object", "properties": properties, "required": required})
}

pub(super) fn text_result(value: &Value) -> Result<Value> {
    let text = match value {
        Value::String(s) => s.clone(),
        other => serde_json::to_string_pretty(other).context("render the tool result as text")?,
    };
    Ok(json!({"content": [{"type": "text", "text": text}]}))
}

pub(super) fn call_tool(name: &str, args: &Value) -> Result<Value> {
    match name {
        "skarbiec_health" => text_result(&json!({"ok": true, "service": "skarbiec"})),
        "skarbiec_list" => text_result(&json!(Vault::open(vault_path())?.list(false))),
        "skarbiec_route_resolve" => text_result(&super::resolve::resolve_tool(args)?),
        "skarbiec_audit" => {
            let empty: Vec<String> = Vec::new();
            text_result(
                &runtime::audit::dispatch("audit list", &HashMap::new(), &empty)?
                    .context("audit produced no result")?,
            )
        }
        "skarbiec_history" => {
            let id = args
                .get("id")
                .and_then(Value::as_str)
                .context("skarbiec_history needs id, the item whose versions to list")?;
            text_result(&Vault::open(vault_path())?.versions(id)?)
        }
        "skarbiec_tags" => text_result(&crate::cli::tools::cmd_tags(&HashMap::new())?),
        "skarbiec_grants_reaching" => {
            let id = args
                .get("id")
                .and_then(Value::as_str)
                .context("skarbiec_grants_reaching needs id, the item to ask about")?;
            let flags = HashMap::from([("item".to_string(), id.to_string())]);
            text_result(
                &crate::access::dispatch("grant", &flags, &["list".to_string()])?
                    .context("grant list produced no result")?,
            )
        }
        "skarbiec_certificates" => {
            let mut flags = HashMap::new();
            if let Some(before) = args.get("expiring_before").and_then(Value::as_str) {
                flags.insert("expiring-before".to_string(), before.to_string());
            }
            text_result(
                &runtime::dispatch("certificates", &flags, &[])?
                    .context("certificates produced no result")?,
            )
        }
        "skarbiec_recipient_items" => {
            let uid = args
                .get("uid")
                .and_then(Value::as_str)
                .context("skarbiec_recipient_items needs uid, the recipient to ask about")?;
            text_result(
                &crate::access::dispatch(
                    "recipient",
                    &HashMap::new(),
                    &["items".to_string(), uid.to_string()],
                )?
                .context("recipient items produced no result")?,
            )
        }
        "skarbiec_duplicates" => text_result(&crate::cmd_duplicates()?),
        "skarbiec_find" => {
            let text = args
                .get("text")
                .and_then(Value::as_str)
                .context("skarbiec_find needs text, what to look for")?;
            let mut flags = HashMap::new();
            if args.get("notes").and_then(Value::as_bool) == Some(true) {
                flags.insert("notes".to_string(), "true".to_string());
            }
            text_result(
                &runtime::dispatch("find", &flags, &[text.to_string()])?
                    .context("find produced no result")?,
            )
        }
        "skarbiec_shares" => text_result(
            &crate::access::dispatch("shares", &HashMap::new(), &[])?
                .context("shares produced no result")?,
        ),
        "skarbiec_unused" => {
            let since = args
                .get("since")
                .and_then(Value::as_str)
                .context("skarbiec_unused needs since, a UTC time of the vault's stamp form")?;
            let grants = crate::access::dispatch(
                "grant",
                &HashMap::from([("idle-since".to_string(), since.to_string())]),
                &["list".to_string()],
            )?;
            let items = crate::cli::list::cmd_list(&HashMap::from([(
                "untouched-since".to_string(),
                since.to_string(),
            )]))?;
            text_result(&json!({"since": since, "grants": grants, "items": items}))
        }
        "skarbiec_expiry" => {
            let before = args
                .get("before")
                .and_then(Value::as_str)
                .map(str::to_string);
            text_result(&crate::runtime::expiry::list(before.as_ref())?)
        }
        "skarbiec_password_age" => text_result(&crate::runtime::age::report(
            args.get("set_before").and_then(Value::as_str),
        )?),
        "skarbiec_logins_for" => {
            let site = args
                .get("site")
                .and_then(Value::as_str)
                .context("skarbiec_logins_for needs site, a host or an address")?;
            text_result(
                &crate::runtime::dispatch(
                    "login",
                    &HashMap::new(),
                    &["list".to_string(), site.to_string()],
                )?
                .context("login list produced no result")?,
            )
        }
        "skarbiec_audit_summary" => {
            // The tool's arguments are the command's flags, by the same names.
            let flags: HashMap<String, String> = args
                .as_object()
                .into_iter()
                .flatten()
                .filter_map(|(name, value)| {
                    value.as_str().map(|text| (name.clone(), text.to_string()))
                })
                .collect();
            text_result(
                &crate::runtime::dispatch("audit summary", &flags, &[])?
                    .context("audit summary produced no result")?,
            )
        }
        "skarbiec_review" => {
            let before = args
                .get("before")
                .and_then(Value::as_str)
                .context("skarbiec_review needs before, a UTC time of the vault's stamp form")?;
            let mut flags = HashMap::from([("before".to_string(), before.to_string())]);
            if args.get("breached").and_then(Value::as_bool) == Some(true) {
                flags.insert("breached".to_string(), "true".to_string());
            }
            text_result(
                &runtime::dispatch("review", &flags, &[])?.context("review produced no result")?,
            )
        }
        "skarbiec_pins" => text_result(&crate::runtime::pins::list()?),
        "skarbiec_codes_missing" => text_result(
            &runtime::dispatch("totp", &HashMap::new(), &["missing".to_string()])?
                .context("totp missing produced no result")?,
        ),
        "skarbiec_site_breaches" => text_result(
            &runtime::dispatch("breach", &HashMap::new(), &["sites".to_string()])?
                .context("breach sites produced no result")?,
        ),
        "skarbiec_password_rules" => {
            let id = args
                .get("id")
                .and_then(Value::as_str)
                .context("skarbiec_password_rules needs id, the login whose rules to read")?;
            text_result(
                &runtime::dispatch(
                    "password",
                    &HashMap::new(),
                    &["rules".to_string(), id.to_string()],
                )?
                .context("password rules produced no result")?,
            )
        }
        "skarbiec_scan" => {
            let path = args
                .get("path")
                .and_then(Value::as_str)
                .context("skarbiec_scan needs path, the file or directory to look in")?;
            let fields = args
                .get("fields")
                .and_then(Value::as_str)
                .context("skarbiec_scan needs fields, the fields whose values are looked for")?;
            let mut flags = HashMap::from([("fields".to_string(), fields.to_string())]);
            if let Some(minimum) = args.get("min_length").and_then(Value::as_str) {
                flags.insert("min-length".to_string(), minimum.to_string());
            }
            text_result(
                &runtime::dispatch("scan", &flags, &[path.to_string()])?
                    .context("scan produced no result")?,
            )
        }
        "skarbiec_token_expiry" => {
            let mut flags = HashMap::new();
            if let Some(before) = args.get("before").and_then(Value::as_str) {
                flags.insert("before".to_string(), before.to_string());
            }
            text_result(
                &runtime::dispatch("expiry", &flags, &["tokens".to_string()])?
                    .context("expiry tokens produced no result")?,
            )
        }
        "skarbiec_exposure" => {
            let id = args
                .get("id")
                .and_then(Value::as_str)
                .context("skarbiec_exposure needs id, the item to answer for")?;
            let mut flags = HashMap::new();
            if let Some(since) = args.get("since").and_then(Value::as_str) {
                flags.insert("since".to_string(), since.to_string());
            }
            let mut answer = runtime::dispatch("exposure", &flags, &[id.to_string()])?
                .context("exposure produced no result")?;
            // An agent gets how many keys open the item and whether one here
            // does, never a key id: no tool hands out key identifiers.
            let keys = answer["keys"].clone();
            answer["keys"] = json!({
                "count": keys["encrypted_to"].as_array().map(Vec::len),
                "openable_here": keys["openable_here"],
            });
            text_result(&answer)
        }
        "skarbiec_rotations" => {
            let mut flags = HashMap::new();
            if args.get("due").and_then(Value::as_bool) == Some(true) {
                flags.insert("due".to_string(), "true".to_string());
            }
            text_result(
                &crate::credential::dispatch(
                    "rotation",
                    &flags,
                    &["list".to_string()],
                    &vault_path(),
                )?
                .context("rotation list produced no result")?,
            )
        }
        // Which tools on this machine ask the vault for their credentials,
        // and which still keep one in plain text: helper status and tool
        // status, never a token.
        "skarbiec_credential_helpers" => text_result(&json!({
            "helpers": crate::runtime::helper::status_all(),
            "tool_tokens": crate::runtime::tooltoken::status_all(),
            "helpers_check": crate::runtime::doctor::helpers_report(),
        })),
        // A bindings file on the server's machine, line by line: whether the
        // program exec starts would get each variable, never a value.
        "skarbiec_bindings_check" => {
            let file = args.get("file").and_then(Value::as_str).context(
                "skarbiec_bindings_check needs file, the absolute path of a bindings file",
            )?;
            if !std::path::Path::new(file).is_absolute() {
                anyhow::bail!("skarbiec_bindings_check needs file as an absolute path; got {file}");
            }
            text_result(
                &crate::runtime::dispatch(
                    "bindings",
                    &HashMap::new(),
                    &["check".to_string(), file.to_string()],
                )?
                .context("bindings check answered nothing")?,
            )
        }
        other => anyhow::bail!("unknown tool: {other}"),
    }
}
