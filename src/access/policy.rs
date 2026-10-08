// Administrative policy for the vault: organization rules enforced before the
// relevant operation. Stored in the vault's `policy` section.
//
// The supported rules are the rows of `POLICY_KEYS` below, and that registry is
// the authority: a rule exists because something in this binary reads it. The
// section is not an open bag of operator metadata. Every command here treats it
// as enforcement — `policy check` decides a candidate on it, and the header of
// this file once advertised a `require_totp` rule that nothing ever read — so a
// key this binary does not consume is a rule an operator believes is in force
// and is not. `policy set` refuses one rather than storing it.
//
// Consumer capabilities are a different surface, enforced by the tokens module.
// Vocabulary here is deliberately neutral to keep policy metadata clear.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::OrUsage;
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

/// One supported policy key: its name, the value shape the reader can actually
/// consume, the test that decides whether a written value clears it, and how
/// a candidate is decided against a stored value.
///
/// The shape is carried beside the test on purpose. A key whose value the
/// reader silently skips is the same defect as a key nothing reads at all:
/// `min_generated_length` is read through `as_u64`, so storing `soon` for it
/// would leave `policy get` showing a configured minimum while
/// `policy check` passes everything. Accepting the key is not enough;
/// the value has to be one the rule can act on.
struct PolicyKey {
    name: &'static str,
    /// What a value must be, phrased for the operator who reads a refusal.
    shape: &'static str,
    accepts: fn(&Value) -> bool,
    /// The verdict on one candidate against the stored value: what the rule
    /// requires, what the candidate has, and whether that clears it.
    decide: fn(&Value, &str) -> Value,
}

/// A whole number, which is what every numeric rule here is read back as.
fn whole_number(value: &Value) -> bool {
    value.is_u64()
}

/// A candidate clears `min_generated_length` when it has at least that many
/// characters.
fn at_least_length(stored: &Value, candidate: &str) -> Value {
    let actual = candidate.chars().count();
    let required = stored.as_u64();
    json!({
        "required": required,
        "actual": actual,
        "ok": required.is_some_and(|minimum| actual as u64 >= minimum),
    })
}

/// The registry. Adding a rule is adding a row here in the same commit that
/// starts reading it; nothing else registers a policy key.
const POLICY_KEYS: &[PolicyKey] = &[PolicyKey {
    name: "min_generated_length",
    shape: "a whole number",
    // Decided on by `policy check` through `at_least_length`.
    accepts: whole_number,
    decide: at_least_length,
}];

/// Every supported key with the shape it demands, for a refusal to name.
fn supported_shown() -> String {
    POLICY_KEYS
        .iter()
        .map(|key| format!("{} ({})", key.name, key.shape))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Why one `policy set` is refused, or `Ok` if a registered rule accepts it.
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

/// `policy get|set|unset|check` is a group: the object is the command and the
/// verb its first positional; the operator routes call the leaves by their
/// whole name ("policy get"). The hyphenated spellings (`policy-get`, …) are
/// still answered, because a host's Weles runs `skarbiec policy-get` against
/// the Skarbiec installed there; they go once every host runs one with the
/// group.
pub fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command == "policy" {
        return group(positionals).map(Some);
    }
    let spelled;
    let command = match command.strip_prefix("policy-") {
        Some(verb) => {
            spelled = format!("policy {verb}");
            spelled.as_str()
        }
        None => command,
    };
    leaf(command, positionals)
}

fn group(positionals: &[String]) -> Result<Value> {
    let Some((verb, positionals)) = positionals.split_first() else {
        return Err(crate::cli::args::Usage(
            "policy needs a subcommand; `skarbiec policy help` lists them".to_string(),
        )
        .into());
    };
    if verb == "help" {
        return Ok(json!({
            "commands": [
                "policy get",
                "policy set <key> <value>",
                "policy unset <key>",
                "policy check < candidate",
            ],
            "usage": "policy get reads the administrative policy, policy set and policy unset write and withdraw one rule the binary enforces, and policy check decides a candidate read from standard input against every rule, without storing it.",
        }));
    }
    leaf(&format!("policy {verb}"), positionals)?.ok_or_else(|| {
        crate::cli::args::Usage(format!(
            "unknown policy command: {verb}; `skarbiec policy help` lists them"
        ))
        .into()
    })
}

fn leaf(command: &str, positionals: &[String]) -> Result<Option<Value>> {
    match command {
        "policy set" => {
            let mut args = positionals.iter();
            let key = args.next().or_usage("usage: policy set <key> <value>")?;
            let raw = args.next().or_usage("usage: policy set <key> <value>")?;
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
        // The inverse of policy set: withdraw one rule. A key that is not set
        // is the state asked for, reported rather than refused.
        "policy unset" => {
            let key = positionals.first().or_usage("usage: policy unset <key>")?;
            let mut vault = load()?;
            let removed = ensure_section(vault.doc_mut(), "policy")
                .remove(key.as_str())
                .is_some();
            if removed {
                vault.save()?;
                crate::runtime::audit::append("policy-unset", &json!({"key": key}))?;
            }
            Ok(Some(json!({"ok": true, "key": key, "removed": removed})))
        }
        "policy get" => {
            let vault = load()?;
            Ok(Some(
                vault
                    .doc()
                    .get("policy")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
            ))
        }
        // Decide one candidate against every rule the policy declares. The
        // candidate is a secret, so it is read from standard input and never
        // from argv; one trailing newline is removed and nothing else, since
        // whitespace inside a password is part of it.
        "policy check" => {
            if !positionals.is_empty() {
                anyhow::bail!(
                    "policy check reads the candidate from standard input, never from an argument: an argument stays in the process table and shell history. Pipe it in: `printf '%s' \"$CANDIDATE\" | skarbiec policy check`"
                );
            }
            let mut read = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut read)
                .map_err(|error| anyhow::anyhow!("reading the candidate from standard input: {error}"))?;
            let candidate = match read.strip_suffix('\n') {
                Some(line) => match line.strip_suffix('\r') {
                    Some(bare) => bare,
                    None => line,
                },
                None => read.as_str(),
            };
            check(candidate).map(Some)
        }
        _ => Ok(None),
    }
}

/// Decide one candidate against every rule the policy declares: `policy check`
/// on the command line and `POST /v1/operator/policy/check` for Desktop. The
/// candidate is never part of the answer.
pub fn check(candidate: &str) -> Result<Value> {
    if candidate.is_empty() {
        anyhow::bail!(
            "policy check needs a candidate, and the one it read was empty: standard input on the command line, the candidate field over the operator API"
        );
    }
    let vault = load()?;
    let stored = vault.doc().get("policy");
    let rules: Vec<Value> = POLICY_KEYS
        .iter()
        .map(|rule| match stored.and_then(|policy| policy.get(rule.name)) {
            Some(value) => {
                let mut verdict = (rule.decide)(value, candidate);
                verdict["key"] = json!(rule.name);
                verdict["configured"] = json!(true);
                verdict
            }
            None => json!({"key": rule.name, "configured": false, "ok": true}),
        })
        .collect();
    let ok = rules.iter().all(|rule| rule["ok"] == json!(true));
    Ok(json!({"ok": ok, "rules": rules}))
}
