// The one item the journey writes and reads back, and the prompts an
// operator answers while it does.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};

pub(super) fn create_and_read_demo(item_id: &str) -> Result<()> {
    let mut vault = crate::core::vault::Vault::open(crate::vault_path())?;
    let owner = vault.owner_uid().to_string();
    let payload = crate::core::items::build_item(
        "note",
        &["value=Skarbiec onboarding note; explicitly not a secret".to_string()],
    )?;
    vault.set_item_written_by(
        item_id,
        "note",
        &payload,
        &[],
        &["onboarding".to_string()],
        &owner,
    )?;
    let _decrypted = vault.get_item(item_id)?;
    crate::runtime::audit::append_sync(
        "onboarding-demo-item-read",
        &json!({"item": item_id, "consumer": "human", "contains_secret": false}),
    )?;
    println!("\nCreated and decrypted non-secret note: {item_id}");
    Ok(())
}

pub(super) fn audit_evidence(item_id: &str) -> Result<bool> {
    let mut flags = HashMap::new();
    flags.insert("op".to_string(), "onboarding-demo-item-read".to_string());
    flags.insert("item".to_string(), item_id.to_string());
    let result = crate::runtime::audit::dispatch("audit-query", &flags, &[])?
        .context("audit query is unavailable")?;
    Ok(result
        .get("matched")
        .and_then(Value::as_u64)
        .unwrap_or_default()
        > 0)
}

pub(super) fn render(screen: &Value) {
    let presentation = screen
        .get("presentation")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let ordered = presentation.into_iter().collect::<BTreeMap<_, _>>();
    let title = ordered
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Skarbiec onboarding");
    let body = ordered.get("body").and_then(Value::as_str).unwrap_or("");
    println!("\n== {title} ==\n{body}");
}

pub(super) fn confirmed(flags: &HashMap<String, String>, prompt: &str) -> Result<bool> {
    if flags.get("yes").is_some_and(|value| value == "true") {
        return Ok(true);
    }
    print!("{prompt}");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

pub(super) fn wait_for_enter(flags: &HashMap<String, String>, prompt: &str) -> Result<()> {
    if flags.get("yes").is_some_and(|value| value == "true") {
        return Ok(());
    }
    print!("{prompt}");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(())
}

pub(super) fn demo_item_id(attempt_id: &str) -> String {
    let prefix = attempt_id.get(..8).unwrap_or(attempt_id);
    format!("onboarding-safe-note-{prefix}")
}
