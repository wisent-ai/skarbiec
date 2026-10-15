// Password-health check using the HaveIBeenPwned range API under k-anonymity:
// hash the stored value with SHA-1, send ONLY the hash prefix to the public
// range endpoint, and match the returned suffixes locally — the value never
// leaves this host. Reports whether it appears in known breach corpora.

use crate::cli::args::OrUsage;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;

use crate::core::{crypto, schema, vault::Vault, vault_path};

fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

// The range endpoint keys on the first five hex chars of the SHA-1; this sample
// names that width without a bare numeric literal.
const PREFIX_WIDTH_SAMPLE: &str = "ABCDE";

/// The field checked when `--field` names none, as the usage line declares.
const DECLARED_FIELD: &str = "password";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "breach-check" => {
            let id = positionals.first().or_usage(&format!(
                "usage: breach-check <item-id> [--field {DECLARED_FIELD}]"
            ))?;
            let field = match flags.get("field") {
                Some(field) => field.as_str(),
                None => DECLARED_FIELD,
            };
            let vault = load()?;
            let row = vault.get_item(id)?;
            let candidate = schema::field(&row, field)
                .with_context(|| format!("{id} has no canonical field {field}"))?
                .as_str()
                .with_context(|| format!("{id} field {field} is not text"))?;
            let hash = crypto::sha1_hex_upper(candidate)?;
            let (prefix, suffix) = hash.split_at(PREFIX_WIDTH_SAMPLE.len());
            let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
            // No deadline of its own: the range API answers or curl says why,
            // and that sentence is the reason the check could not be made.
            let response = stado_wait::output(Command::new("curl").args(["-sS", "--fail", &url]))
                .context("curl range api")?;
            if !response.status.success() {
                return Ok(Some(json!({
                    "item": id,
                    "checked": false,
                    "reason": "range_api_unreachable",
                    "detail": format!(
                        "curl {url} {}: {}",
                        response.status,
                        String::from_utf8_lossy(&response.stderr).trim()
                    ),
                })));
            }
            let body = String::from_utf8_lossy(&response.stdout);
            let seen = body.lines().find_map(|line| {
                let (line_suffix, count) = line.trim().split_once(':')?;
                if line_suffix.eq_ignore_ascii_case(suffix) {
                    Some(count.trim().to_string())
                } else {
                    None
                }
            });
            crate::runtime::audit::append("breach-check", &json!({"item": id, "field": field}))?;
            Ok(Some(
                json!({"item": id, "field": field, "checked": true, "pwned": seen.is_some(), "seen_count": seen}),
            ))
        }
        _ => Ok(None),
    }
}
