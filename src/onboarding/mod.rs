use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

const PRODUCT_ID: &str = "skarbiec";
const JOURNEY_ID: &str = "first-use";
const STATE_SCHEMA: &str = "skarbiec.onboarding-state.v1";
const CANONICAL_JOURNEY: &str = include_str!("../onboarding_first_use.json");

mod demo;
mod journey;
mod state;

use demo::{audit_evidence, confirmed, create_and_read_demo, demo_item_id, render, wait_for_enter};
use journey::{canonical_definition, screen_by_id};
use state::{advance_state, complete_state, load_or_start_state};

pub fn run(flags: &HashMap<String, String>) -> Result<Value> {
    if let Some(path) = flags.get("import") {
        return crate::core::importer::run(flags, std::slice::from_ref(path));
    }
    let definition = canonical_definition()?;
    let reset = flags.get("reset").is_some_and(|value| value == "true");
    let revision = format!("skarbiec-{}", env!("CARGO_PKG_VERSION"));
    let mut state = load_or_start_state(&definition, &revision, reset)?;

    if state.get("status").and_then(Value::as_str) == Some("completed") {
        return Ok(json!({
            "ok": true,
            "status": "completed",
            "next": "skarbiec acquisition-request --help"
        }));
    }

    loop {
        let screen_id = state
            .get("current_screen_id")
            .and_then(Value::as_str)
            .context("onboarding state has no current screen")?
            .to_string();
        let attempt_id = state
            .get("attempt_id")
            .and_then(Value::as_str)
            .context("onboarding state has no attempt id")?
            .to_string();
        let screen = screen_by_id(&definition, &screen_id)?.clone();
        render(&screen);

        match screen.get("screen_kind").and_then(Value::as_str) {
            Some("first_action") => {
                if !crate::vault_path().exists() {
                    println!("\nA vault is required for the real first result.");
                    println!("Run: skarbiec init <owner-uid>");
                    return Ok(json!({
                        "ok": true,
                        "status": "awaiting_vault",
                        "resume": "skarbiec onboarding"
                    }));
                }
                // The question the published journey declares for this
                // screen, asked first and answered as a yes/no.
                //
                // An export-file prompt used to come before it, and a bare
                // `n` -- the ordinary answer to a `[y/N]` question -- was
                // read as the name of a file to import. So an operator
                // declining the walkthrough got the importer pointed at a
                // file called `n`, and `skarbiec onboarding` never reached
                // the screen the journey publishes: the first-use journey
                // timed out waiting for `"status": "paused"` while the
                // process sat on a prompt no published screen mentions.
                // Import has its own entry points, `skarbiec import` and
                // `skarbiec onboarding --import <export-file>`, and this
                // screen names the second one instead of consuming an answer
                // meant for the question above it.
                if !confirmed(
                    flags,
                    "Write and read one non-secret onboarding note? [y/N] ",
                )? {
                    println!(
                        "\nAlready hold credentials elsewhere? \
                         `skarbiec onboarding --import <export-file>` brings them in."
                    );
                    return Ok(json!({
                        "ok": true,
                        "status": "paused",
                        "resume": "skarbiec onboarding"
                    }));
                }
                let item_id = demo_item_id(&attempt_id);
                create_and_read_demo(&item_id)?;
                let evidence = Map::from_iter([("demo_item_read".to_string(), Value::Bool(true))]);
                advance_state(&definition, &screen, &mut state, &evidence, &revision)?
                    .context("safe demo evidence did not satisfy the published journey")?;
            }
            Some("first_success") => {
                let item_id = demo_item_id(&attempt_id);
                let audit = audit_evidence(&item_id)?;
                println!("\nObserved hash-chained audit entry for item: {item_id}");
                println!("The note value is not present in the audit record.");
                wait_for_enter(flags, "Press Enter to finish onboarding.")?;
                let evidence =
                    Map::from_iter([("audit_entry_observed".to_string(), Value::Bool(audit))]);
                if !complete_state(&screen, &mut state, &evidence, &revision)? {
                    bail!("published first-success evidence was not satisfied");
                }
                return Ok(json!({
                    "ok": true,
                    "status": "completed",
                    "first_success": "audit_entry_observed",
                    "demo_item": item_id,
                    "next": "skarbiec acquisition-request --help"
                }));
            }
            Some(_) => {
                wait_for_enter(flags, "Press Enter to continue.")?;
                advance_state(&definition, &screen, &mut state, &Map::new(), &revision)?
                    .context("published journey has no eligible next screen")?;
            }
            None => bail!("published onboarding screen has no kind"),
        }
    }
}

