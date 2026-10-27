// The one item the journey writes and reads back, and the prompts an
// operator answers while it does.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, Write};

pub(super) fn create_and_read_demo(item_id: &str) -> Result<()> {
    let mut vault = crate::core::vault::Vault::open(crate::vault_path())?;
    let owner = vault.owner_uid().to_string();
    let payload = crate::core::items::build_item(
        "note",
        &[format!(
            "value=Skarbiec onboarding note for {item_id}; explicitly not a secret"
        )],
    )?;
    vault.set_item_written_by(
        item_id,
        "note",
        &payload,
        &[],
        &["onboarding".to_string()],
        &owner,
    )?;
    let decrypted = vault.get_item(item_id)?;
    anyhow::ensure!(
        decrypted == payload,
        "onboarding read returned a different payload for demo item {item_id}"
    );
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
    let result = crate::runtime::audit::dispatch("audit list", &flags, &[])?
        .context("audit query is unavailable")?;
    let entries = result
        .get("entries")
        .and_then(Value::as_array)
        .context("the audit query answered without its entries")?;
    Ok(!entries.is_empty())
}

/// One onboarding screen as the definition presents it: its title and body. A screen
/// the definition declares without them is refused naming it, never shown blank.
pub(super) fn render(screen: &Value) -> Result<()> {
    let presentation = screen
        .get("presentation")
        .and_then(Value::as_object)
        .with_context(|| format!("onboarding screen {screen} declares no presentation"))?;
    let title = presentation
        .get("title")
        .and_then(Value::as_str)
        .with_context(|| format!("onboarding screen {screen} declares no title"))?;
    let body = presentation
        .get("body")
        .and_then(Value::as_str)
        .with_context(|| format!("onboarding screen {screen} declares no body"))?;
    println!("\n== {title} ==\n{body}");
    Ok(())
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
    format!("onboarding-safe-note-{attempt_id}")
}
