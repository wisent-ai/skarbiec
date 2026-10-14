// `/v1/operator/credential`: one credential operation of the vault in view,
// named by the request's `operation` and read as a declared enum, so the set
// of operations and the dispatch over them are one declaration.

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

use super::calls::{credential, flags, text};

/// What the console asks of one credential.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Operation {
    Status,
    Acquire,
    Rotate,
    Resume,
    Get,
    SetJson,
    Totp,
}

pub(super) fn answer(parsed: &Value) -> Result<Value> {
    let operation: Operation = Operation::deserialize(&parsed["operation"]).with_context(|| {
        format!(
            "operator credential operation {} is none of status, acquire, rotate, resume, get, set-json, totp; a field write sends the whole payload with set-json",
            parsed["operation"]
        )
    })?;
    match operation {
        Operation::Status | Operation::Acquire | Operation::Rotate | Operation::Resume => {
            // Always this vault file: the console reports on and drives the
            // vault in view, never a canonical Skarbiec somewhere else.
            let mut call_flags = flags(parsed, &["provider", "consumer", "purpose", "account"]);
            call_flags.insert("local".to_string(), "true".to_string());
            credential(
                &call_flags,
                &[text(parsed, "operation")?, text(parsed, "item")?],
            )
        }
        Operation::Get => crate::core::values::dispatch(
            "credential",
            &flags(parsed, &["field"]),
            &["get".to_string(), text(parsed, "item")?],
        )?
        .context("get operation failed"),
        Operation::SetJson => {
            let mut call_flags = flags(
                parsed,
                &["type", "tags", "recipients", "if-absent", "if-unchanged"],
            );
            // The payload travels to the dispatcher as its own flag.
            if let Some(payload) = parsed.get("payload") {
                call_flags.insert("__payload__".to_string(), payload.to_string());
            }
            let positionals = vec!["set-json".to_string(), text(parsed, "item")?];
            crate::core::values::dispatch("credential", &call_flags, &positionals)?
                .context("set-json operation failed")
        }
        Operation::Totp => {
            crate::runtime::totp::dispatch("totp", &flags(parsed, &[]), &[text(parsed, "item")?])?
                .context("totp operation failed")
        }
    }
}
