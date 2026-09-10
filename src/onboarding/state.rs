// Where an operator's progress through the journey is kept, and how a screen
// moves it forward.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use super::journey::{evidence_satisfied, next_screen_id, screen_by_id};
use super::{JOURNEY_ID, PRODUCT_ID, STATE_SCHEMA};

pub(super) fn advance_state(
    definition: &Value,
    screen: &Value,
    state: &mut Value,
    evidence: &Map<String, Value>,
    revision: &str,
) -> Result<Option<String>> {
    if !evidence_satisfied(screen, evidence)? {
        return Ok(None);
    }
    let Some(next) = next_screen_id(screen)? else {
        return Ok(None);
    };
    screen_by_id(definition, &next)?;
    let object = state
        .as_object_mut()
        .context("onboarding state is not an object")?;
    object.insert("current_screen_id".to_string(), Value::String(next.clone()));
    object.insert("revision".to_string(), Value::String(revision.to_string()));
    save_state(state)?;
    Ok(Some(next))
}

pub(super) fn complete_state(
    screen: &Value,
    state: &mut Value,
    evidence: &Map<String, Value>,
    revision: &str,
) -> Result<bool> {
    if !evidence_satisfied(screen, evidence)? {
        return Ok(false);
    }
    let object = state
        .as_object_mut()
        .context("onboarding state is not an object")?;
    object.insert("status".to_string(), Value::String("completed".to_string()));
    object.insert("revision".to_string(), Value::String(revision.to_string()));
    save_state(state)?;
    Ok(true)
}

pub(super) fn load_or_start_state(
    definition: &Value,
    revision: &str,
    reset: bool,
) -> Result<Value> {
    let path = state_path();
    if !reset && path.exists() {
        let existing: Value = serde_json::from_str(
            &fs::read_to_string(&path)
                .with_context(|| format!("read onboarding state {}", path.display()))?,
        )
        .context("parse onboarding state")?;
        if existing.get("schema").and_then(Value::as_str) != Some(STATE_SCHEMA)
            || existing.get("product_id").and_then(Value::as_str) != Some(PRODUCT_ID)
            || existing.get("journey_id").and_then(Value::as_str) != Some(JOURNEY_ID)
        {
            bail!("stored onboarding state identity mismatch; use --reset to replace it");
        }
        let current = existing
            .get("current_screen_id")
            .and_then(Value::as_str)
            .context("stored onboarding state has no current screen")?;
        screen_by_id(definition, current)?;
        return Ok(existing);
    }

    let entry = definition
        .get("entry_screen_id")
        .and_then(Value::as_str)
        .context("canonical onboarding journey has no entry screen")?;
    let journey_version = definition
        .get("journey_version")
        .and_then(Value::as_str)
        .context("canonical onboarding journey has no version")?;
    let state = json!({
        "schema": STATE_SCHEMA,
        "product_id": PRODUCT_ID,
        "journey_id": JOURNEY_ID,
        "journey_version": journey_version,
        "source_revision": definition.get("source_revision"),
        "subject_hash": subject_hash()?,
        "attempt_id": crate::core::crypto::random_token()?,
        "current_screen_id": entry,
        "status": "in_progress",
        "revision": revision,
    });
    save_state(&state)?;
    Ok(state)
}

pub(super) fn save_state(state: &Value) -> Result<()> {
    let path = state_path();
    let parent = path
        .parent()
        .context("onboarding state path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create onboarding state directory {}", parent.display()))?;
    fs::set_permissions(
        parent,
        fs::Permissions::from_mode(u32::from_str_radix("700", 8)?),
    )?;
    let suffix = crate::core::crypto::random_token()?;
    let temporary = path.with_extension(format!("json.tmp-{}", &suffix[..12]));
    let body = format!("{}\n", serde_json::to_string(state)?);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(u32::from_str_radix("600", 8)?)
        .open(&temporary)
        .with_context(|| format!("create onboarding state {}", temporary.display()))?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    fs::rename(&temporary, &path)
        .with_context(|| format!("replace onboarding state {}", path.display()))?;
    Ok(())
}

pub(super) fn subject_hash() -> Result<String> {
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown-user".to_string());
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".to_string());
    crate::core::crypto::sha256_hex(&format!("skarbiec-onboarding\0{user}\0{host}"))
}

pub(super) fn state_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local/share/skarbiec/onboarding.json")
}
