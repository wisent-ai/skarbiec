use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::HashMap;

pub(crate) fn local(path: &str, body: &Value) -> Result<Value> {
    let flags = body
        .get("flags")
        .and_then(Value::as_object)
        .context("owner item request requires flags object")?;
    let flags: HashMap<String, String> = flags
        .iter()
        .map(|(key, value)| {
            Ok((
                key.clone(),
                value
                    .as_str()
                    .with_context(|| format!("owner item flag {key} must be text"))?
                    .to_string(),
            ))
        })
        .collect::<Result<_>>()?;
    let positionals = body
        .get("positionals")
        .and_then(Value::as_array)
        .context("owner item request requires positionals array")?;
    let positionals: Vec<String> = positionals
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .context("owner item positional must be text")
        })
        .collect::<Result<_>>()?;
    match path {
        "/v1/operator/items/get" => crate::cli::reads::get_value(&flags, &positionals),
        "/v1/operator/items/list" => crate::cli::list::cmd_list(&flags),
        "/v1/operator/items/set-json" => {
            let id = positionals
                .first()
                .context("set requires an item id")?;
            let encoded = body
                .get("payload")
                .and_then(Value::as_str)
                .context("set requires its encoded stdin payload")?;
            crate::cli::items::set_json_value(&flags, id, encoded)
        }
        "/v1/operator/items/retag" => crate::cli::items::retag_value(&flags, &positionals),
        "/v1/operator/totp/seed-state" => {
            let mut asked = vec![SEED_LEAF.to_string()];
            asked.extend(positionals);
            crate::runtime::totp::dispatch(TOTP, &flags, &asked)?.context("totp seed answered nothing")
        }
        _ => bail!("unknown owner item operation {path}"),
    }
}

/// The TOTP seed diagnostic's command and leaf, which a forwarded request
/// runs on the owner as the command line runs it.
pub(crate) const TOTP: &str = "totp";
pub(crate) const SEED_LEAF: &str = "seed";
