use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

const PRODUCT_ID: &str = "skarbiec";
const JOURNEY_ID: &str = "first-use";
const STATE_SCHEMA: &str = "skarbiec.onboarding-state.v1";
const FALLBACK: &str = include_str!("onboarding_first_use.json");

pub fn run(flags: &HashMap<String, String>) -> Result<Value> {
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
                if !confirmed(
                    flags,
                    "Write and read one non-secret onboarding note? [y/N] ",
                )? {
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

fn canonical_definition() -> Result<Value> {
    let definition: Value =
        serde_json::from_str(FALLBACK).context("parse canonical onboarding journey")?;
    if definition.get("schema_version").and_then(Value::as_u64) != Some(1)
        || definition.get("product_id").and_then(Value::as_str) != Some(PRODUCT_ID)
        || definition.get("journey_id").and_then(Value::as_str) != Some(JOURNEY_ID)
    {
        bail!("canonical onboarding journey identity mismatch");
    }
    let entry = definition
        .get("entry_screen_id")
        .and_then(Value::as_str)
        .context("canonical onboarding journey has no entry screen")?;
    let screens = definition
        .get("screens")
        .and_then(Value::as_array)
        .context("canonical onboarding journey has no screens")?;
    let mut ids = HashSet::new();
    for screen in screens {
        let id = screen
            .get("screen_id")
            .and_then(Value::as_str)
            .context("canonical onboarding screen has no id")?;
        if !ids.insert(id) {
            bail!("duplicate canonical onboarding screen id: {id}");
        }
        screen
            .get("screen_kind")
            .and_then(Value::as_str)
            .context("canonical onboarding screen has no kind")?;
        screen
            .get("presentation")
            .and_then(Value::as_object)
            .context("canonical onboarding screen has no presentation")?;
    }
    if !ids.contains(entry) {
        bail!("canonical onboarding entry screen does not exist");
    }
    for screen in screens {
        for transition in screen
            .get("transitions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let next = transition
                .get("next_screen_id")
                .and_then(Value::as_str)
                .context("canonical onboarding transition has no target")?;
            if !ids.contains(next) {
                bail!("canonical onboarding transition target does not exist: {next}");
            }
        }
    }
    Ok(definition)
}

fn screen_by_id<'a>(definition: &'a Value, screen_id: &str) -> Result<&'a Value> {
    definition
        .get("screens")
        .and_then(Value::as_array)
        .and_then(|screens| {
            screens
                .iter()
                .find(|screen| screen.get("screen_id").and_then(Value::as_str) == Some(screen_id))
        })
        .with_context(|| format!("published onboarding screen is unavailable: {screen_id}"))
}

fn next_screen_id(screen: &Value) -> Result<Option<String>> {
    let Some(transitions) = screen.get("transitions").and_then(Value::as_array) else {
        return Ok(None);
    };
    transitions
        .iter()
        .max_by_key(|transition| {
            transition
                .get("priority")
                .and_then(Value::as_i64)
                .unwrap_or_default()
        })
        .map(|transition| {
            transition
                .get("next_screen_id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .context("canonical onboarding transition has no target")
        })
        .transpose()
}

fn evidence_satisfied(screen: &Value, evidence: &Map<String, Value>) -> Result<bool> {
    let Some(rule) = screen
        .get("completion_evidence")
        .filter(|value| !value.is_null())
    else {
        return Ok(true);
    };
    if rule.get("kind").and_then(Value::as_str) != Some("fact")
        || rule.get("operator").and_then(Value::as_str) != Some("eq")
    {
        bail!("unsupported canonical onboarding evidence rule");
    }
    let fact = rule
        .get("fact")
        .and_then(Value::as_str)
        .context("canonical onboarding evidence rule has no fact")?;
    let expected = rule
        .get("value")
        .context("canonical onboarding evidence rule has no expected value")?;
    Ok(evidence.get(fact) == Some(expected))
}

fn advance_state(
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

fn complete_state(
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

fn load_or_start_state(definition: &Value, revision: &str, reset: bool) -> Result<Value> {
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

fn save_state(state: &Value) -> Result<()> {
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

fn create_and_read_demo(item_id: &str) -> Result<()> {
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

fn audit_evidence(item_id: &str) -> Result<bool> {
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

fn render(screen: &Value) {
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

fn confirmed(flags: &HashMap<String, String>, prompt: &str) -> Result<bool> {
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

fn wait_for_enter(flags: &HashMap<String, String>, prompt: &str) -> Result<()> {
    if flags.get("yes").is_some_and(|value| value == "true") {
        return Ok(());
    }
    print!("{prompt}");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(())
}

fn demo_item_id(attempt_id: &str) -> String {
    let prefix = attempt_id.get(..8).unwrap_or(attempt_id);
    format!("onboarding-safe-note-{prefix}")
}

fn subject_hash() -> Result<String> {
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown-user".to_string());
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".to_string());
    crate::core::crypto::sha256_hex(&format!("skarbiec-onboarding\0{user}\0{host}"))
}

fn state_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local/share/skarbiec/onboarding.json")
}

