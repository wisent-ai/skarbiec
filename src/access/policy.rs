// Administrative policy for the vault: organization rules enforced before the
// relevant operation. Stored in the vault's `policy` section.
//
// The supported rules are the rows of `POLICY_KEYS` below, and that registry is
// the authority: a rule exists because something in this binary reads it. The
// section is not an open bag of operator metadata. Every command here treats it
// as enforcement — `policy-check-length` decides on it, and the header of this
// file once advertised a `require_totp` rule that nothing ever read — so a key
// this binary does not consume is a rule an operator believes is in force and
// is not. `policy-set` refuses one rather than storing it.
//
// Consumer capabilities are a different surface, enforced by the tokens module.
// Vocabulary here is deliberately neutral to keep policy metadata clear.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{vault::Vault, vault_path};

fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

fn ensure_section<'a>(doc: &'a mut Value, key: &str) -> &'a mut serde_json::Map<String, Value> {
    let object = doc.as_object_mut().expect("vault doc is object");
    object.entry(key).or_insert_with(|| json!({}));
    object
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .expect("section is object")
}

// Minimum generated length the policy requires, if configured.
pub fn min_generated_length(vault: &Vault) -> Option<usize> {
    vault
        .doc()
        .get("policy")
        .and_then(|p| p.get("min_generated_length"))
        .and_then(Value::as_u64)
        .map(|n| n as usize)
}

/// One supported policy key: its name, the value shape the reader can actually
/// consume, and the test that decides whether a written value clears it.
///
/// The shape is carried beside the test on purpose. A key whose value the
/// reader silently skips is the same defect as a key nothing reads at all:
/// `min_generated_length` is read through `as_u64`, so storing `soon` for it
/// would leave `policy-get` showing a configured minimum while
/// `policy-check-length` passes everything. Accepting the key is not enough;
/// the value has to be one the rule can act on.
struct PolicyKey {
    name: &'static str,
    /// What a value must be, phrased for the operator who reads a refusal.
    shape: &'static str,
    accepts: fn(&Value) -> bool,
}

/// A whole number, which is what every numeric rule here is read back as.
fn whole_number(value: &Value) -> bool {
    value.is_u64()
}

/// The registry. Adding a rule is adding a row here in the same commit that
/// starts reading it; nothing else registers a policy key.
const POLICY_KEYS: &[PolicyKey] = &[PolicyKey {
    name: "min_generated_length",
    shape: "a whole number",
    // Read by `min_generated_length` below and decided on by
    // `policy-check-length`.
    accepts: whole_number,
}];

/// Every supported key with the shape it demands, for a refusal to name.
fn supported_shown() -> String {
    POLICY_KEYS
        .iter()
        .map(|key| format!("{} ({})", key.name, key.shape))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Why one `policy-set` is refused, or `Ok` if a registered rule accepts it.
///
/// The refusal names every supported key and its shape, because a refusal that
/// withholds the allowed set only moves the guessing one step along.
fn policy_refusal(key: &str, raw: &str, value: &Value) -> Result<(), String> {
    let Some(registered) = POLICY_KEYS.iter().find(|entry| entry.name == key) else {
        return Err(format!(
            "policy key `{key}` is not a rule this binary enforces, so setting it would report success and change nothing. Supported keys: {}. Register a key here in the commit that starts reading it.",
            supported_shown()
        ));
    };
    if (registered.accepts)(value) {
        return Ok(());
    }
    Err(format!(
        "policy key `{key}` requires {}; `{raw}` is not one, and the rule would be stored but never applied. Supported keys: {}.",
        registered.shape,
        supported_shown()
    ))
}

/// Interpret a policy value string as bool / number / string (in that order).
fn coerce(raw: &str) -> Value {
    if raw == "true" || raw == "false" {
        return json!(raw == "true");
    }
    if let Ok(n) = raw.parse::<u64>() {
        return json!(n);
    }
    json!(raw)
}

pub fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "policy-set" => {
            let mut args = positionals.iter();
            let key = args.next().context("usage: policy-set <key> <value>")?;
            let raw = args.next().context("usage: policy-set <key> <value>")?;
            let value = coerce(raw);
            if let Err(refusal) = policy_refusal(key, raw, &value) {
                anyhow::bail!("{refusal}");
            }
            let mut vault = load()?;
            ensure_section(vault.doc_mut(), "policy").insert(key.clone(), value);
            vault.save()?;
            crate::runtime::audit::append("policy-set", &json!({"key": key}))?;
            Ok(Some(json!({"ok": true, "key": key})))
        }
        "policy-get" => {
            let vault = load()?;
            Ok(Some(
                vault
                    .doc()
                    .get("policy")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
            ))
        }
        // Check a candidate string against the configured minimum length. Used
        // by generation and by operators validating a value before storing it.
        "policy-check-length" => {
            let candidate = positionals
                .first()
                .context("usage: policy-check-length <candidate>")?;
            let vault = load()?;
            let length = candidate.chars().count();
            let verdict = match min_generated_length(&vault) {
                Some(minimum) => {
                    json!({"required": minimum, "actual": length, "ok": length >= minimum})
                }
                None => json!({"required": Value::Null, "actual": length, "ok": true}),
            };
            Ok(Some(verdict))
        }
        _ => Ok(None),
    }
}
