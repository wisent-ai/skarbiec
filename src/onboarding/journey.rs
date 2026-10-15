// The journey definition this build ships: its screens, the order they run
// in, and what counts as evidence that one is finished.

use anyhow::{bail, Context, Result};
use serde_json::{Map, Value};
use std::collections::HashSet;

use super::{CANONICAL_JOURNEY, JOURNEY_ID, PRODUCT_ID};

/// The priority `transition` of `screen` declares, refused naming the screen
/// and its target when it declares none or one that is not a whole number.
/// Read as the lowest, a transition that lost its priority decided the next
/// screen whenever it was the only one or tied with another.
fn priority(screen: &str, transition: &Value) -> Result<i64> {
    let target = transition
        .get("next_screen_id")
        .and_then(Value::as_str)
        .with_context(|| {
            format!("canonical onboarding transition of screen {screen} has no target")
        })?;
    transition
        .get("priority")
        .and_then(Value::as_i64)
        .with_context(|| {
            format!(
                "canonical onboarding transition from {screen} to {target} declares no whole-number priority"
            )
        })
}

/// The first-use journey compiled into this binary, checked against what the
/// reader relies on. The definition is embedded at build time, so it is always
/// the file this code was written with: who the journey is for, that every
/// screen has an id, a kind and a presentation, and that every transition
/// names an existing target and a priority.
pub(super) fn canonical_definition() -> Result<Value> {
    let definition: Value =
        serde_json::from_str(CANONICAL_JOURNEY).context("parse canonical onboarding journey")?;
    if definition.get("product_id").and_then(Value::as_str) != Some(PRODUCT_ID)
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
        let id = screen
            .get("screen_id")
            .and_then(Value::as_str)
            .context("canonical onboarding screen has no id")?;
        for transition in screen
            .get("transitions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            priority(id, transition)?;
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

pub(super) fn screen_by_id<'a>(definition: &'a Value, screen_id: &str) -> Result<&'a Value> {
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

/// The target of the highest-priority transition; of equal priorities, the
/// last one listed.
pub(super) fn next_screen_id(screen: &Value) -> Result<Option<String>> {
    let Some(transitions) = screen.get("transitions").and_then(Value::as_array) else {
        return Ok(None);
    };
    let id = screen
        .get("screen_id")
        .and_then(Value::as_str)
        .context("canonical onboarding screen has no id")?;
    let mut chosen: Option<(i64, &Value)> = None;
    for transition in transitions {
        let rank = priority(id, transition)?;
        if chosen.is_none_or(|(best, _)| rank >= best) {
            chosen = Some((rank, transition));
        }
    }
    chosen
        .map(|(_, transition)| {
            transition
                .get("next_screen_id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .context("canonical onboarding transition has no target")
        })
        .transpose()
}

pub(super) fn evidence_satisfied(screen: &Value, evidence: &Map<String, Value>) -> Result<bool> {
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
