// One security review of the whole vault: the questions an owner asks on a
// schedule, answered by the commands that already answer each one, in one
// report. Every section runs even when another fails, and a failed section
// carries its own error, so one broken check never hides the others.

use anyhow::Result;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::core::{clock, vault_path};

mod alert;

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    _positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "review" => review(flags).map(Some),
        _ => Ok(None),
    }
}

/// `skarbiec review --before <iso8601> [--breached] [--alert]`.
///
/// `--before` is the moment the review is held to: a certificate must outlive
/// it, and a value last written before it is reported as not rotated since.
/// It is the caller's to state, because how old is too old is a decision.
fn review(flags: &HashMap<String, String>) -> Result<Value> {
    let before = match flags.get("before") {
        Some(before) if clock::is_iso(before) => before.clone(),
        Some(before) => {
            return Err(crate::cli::args::Usage(format!(
                "--before {before} is not a UTC time of the form {}",
                clock::now_iso()
            ))
            .into())
        }
        None => {
            return Err(crate::cli::args::Usage(
                "usage: review --before <iso8601> [--breached] [--alert]: the moment certificates must outlive and values must have been written after"
                    .to_string(),
            )
            .into())
        }
    };
    let flag = |key: &str, value: &str| HashMap::from([(key.to_string(), value.to_string())]);
    let none: Vec<String> = Vec::new();
    let mut sections = Map::new();
    let mut failed = Vec::new();
    let mut section = |name: &str, answer: Result<Option<Value>>| {
        let entry = match answer {
            Ok(Some(value)) => value,
            Ok(None) => {
                failed.push(name.to_string());
                json!({"error": "the command behind this section answered nothing"})
            }
            Err(error) => {
                failed.push(name.to_string());
                json!({"error": format!("{error:#}")})
            }
        };
        sections.insert(name.to_string(), entry);
    };
    // `--breached` asks Have I Been Pwned too, as `health --breached` does;
    // without it the review stays on this machine.
    let mut health = HashMap::new();
    let breached = crate::cli::args::flag_set(flags, "breached");
    if breached {
        health.insert("breached".to_string(), "true".to_string());
    }
    section("secret_health", crate::runtime::dispatch("health", &health, &none));
    // With `--breached`, also the logins whose site was breached after their
    // password was set, from Have I Been Pwned's public list of breaches.
    if breached {
        section("breached_sites", crate::runtime::dispatch("breach", &HashMap::new(), &["sites".to_string()]));
    }
    section(
        "certificates_ending_before",
        crate::runtime::dispatch("certificates", &flag("expiring-before", &before), &none),
    );
    section(
        "tokens_ending_before",
        crate::runtime::dispatch("expiry", &flag("before", &before), &["tokens".to_string()]),
    );
    section(
        "keys_ending_before",
        crate::runtime::dispatch("keys", &flag("expiring-before", &before), &none),
    );
    section(
        "items_expiring_before",
        crate::runtime::expiry::list(Some(&before)).map(Some),
    );
    section(
        "written_before",
        crate::cli::list::cmd_list(&flag("updated-before", &before)).map(Some),
    );
    section(
        "expired_grants",
        crate::access::dispatch("grant", &flag("expired", "true"), &["list".to_string()]),
    );
    section(
        "grants_naming_missing_items",
        crate::access::dispatch("grant", &flag("dangling", "true"), &["list".to_string()]),
    );
    // What nothing has used since the moment: a grant still opening items
    // for a bearer nobody presents, and a secret nobody reads.
    section(
        "grants_unused_since",
        crate::access::dispatch("grant", &flag("idle-since", &before), &["list".to_string()]),
    );
    section(
        "items_unused_since",
        crate::cli::list::cmd_list(&flag("untouched-since", &before)).map(Some),
    );
    // Passwords that have stood since before the moment: where a rotation
    // starts.
    section(
        "passwords_set_before",
        crate::runtime::age::report(Some(before.as_str())).map(Some),
    );
    // Logins autofill cannot offer anywhere: they name no site.
    section("logins_offered_nowhere", crate::runtime::logins::offered_nowhere().map(Some));
    section(
        "rotations_due",
        crate::credential::dispatch("rotation", &flag("due", "true"), &["list".to_string()], &vault_path()),
    );
    section("emergency_grants", crate::access::dispatch("emergency list", &HashMap::new(), &none));
    // Every login and identity's seed state, and every share that ends on
    // its own: an ended one still listed is one maintain has not revoked.
    section("second_factors", crate::runtime::dispatch("totp", &HashMap::new(), &["seed".to_string()]));
    section("timed_shares", crate::access::dispatch("shares", &HashMap::new(), &none));
    crate::runtime::audit::append("review", &json!({"before": before, "failed_sections": failed}))?;
    let mut report = json!({
        "ok": failed.is_empty(),
        "before": before,
        "reviewed_at": clock::now_iso(),
        "failed_sections": failed,
        "sections": sections,
    });
    // `--alert`: the findings go to the channel `alert set` names.
    if crate::cli::args::flag_set(flags, "alert") {
        report["alert"] = alert::post(&report);
    }
    Ok(report)
}
