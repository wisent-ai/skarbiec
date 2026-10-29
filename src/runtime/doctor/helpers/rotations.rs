// Whether the rotation policies this vault keeps are being run. Declaring a
// policy installs no trigger: due policies run in every `skarbiec maintain`
// pass (and in `rotation run`), so they run only when a Stado schedule, cron
// or launchd calls one of those. A policy still waiting a whole interval after
// it fell due means nothing calls it; one whose last attempt failed means the
// rotation refuses, in the words recorded on it. Both are named here, so a
// credential that should have changed and did not is seen before it leaks.

use serde_json::Value;

use super::super::{check, FAIL, NOT_CONFIGURED, PASS};

const NAME: &str = "rotations";

pub(in crate::runtime::doctor) fn rotations_check() -> Value {
    let listed = match crate::credential::dispatch(
        "rotation",
        &Default::default(),
        &["list".to_string()],
        &crate::core::vault_path(),
    ) {
        Ok(Some(listed)) => listed,
        Ok(None) => return check(NAME, FAIL, "rotation list answered nothing".into()),
        Err(error) => return check(NAME, FAIL, format!("{error:#}")),
    };
    let Some(policies) = listed["policies"]
        .as_array()
        .filter(|policies| !policies.is_empty())
    else {
        return check(NAME, NOT_CONFIGURED, "no item has a rotation policy".into());
    };
    let runs_here = listed["runs_here"].as_bool() == Some(true);
    let now = crate::core::clock::now_epoch();
    let mut problems = Vec::new();
    for policy in policies {
        let item = &policy["item"];
        if let Some(error) = policy["last_error"].as_str() {
            problems.push(format!("{item}'s last rotation failed: {error}"));
            continue;
        }
        let every = policy["every_days"]
            .as_i64()
            .and_then(|days| days.checked_mul(time::Duration::DAY.whole_seconds()));
        let overdue_since = every
            .and_then(|every| now.checked_sub(every))
            .and_then(crate::core::clock::iso_at);
        if let (Some(next), Some(since)) = (policy["next_due_at"].as_str(), overdue_since) {
            if runs_here && next < since.as_str() {
                problems.push(format!(
                    "{item} fell due at {next}, more than its interval ago, and has not rotated: nothing runs `skarbiec maintain` or `skarbiec rotation run` on this host — a Stado schedule, cron or launchd entry must"
                ));
            }
        }
    }
    // A failed rotation is posted only if the alert can still read its
    // webhook; one that cannot would fail silently exactly when needed.
    let alerted = match crate::runtime::alert::check() {
        Err(error) => {
            problems.push(format!("the alert setting cannot be read: {error:#}"));
            String::new()
        }
        Ok(None) => ", no alert set".to_string(),
        Ok(Some((named, Some(problem)))) => {
            problems.push(format!(
                "the alert posts through {named}, which cannot be used: {problem}"
            ));
            String::new()
        }
        Ok(Some((named, None))) => format!(", failures posted through {named}"),
    };
    if problems.is_empty() {
        return check(
            NAME,
            PASS,
            format!(
                "{} rotation policies, none failing or left waiting past their interval{alerted}",
                policies.len()
            ),
        );
    }
    check(NAME, FAIL, problems.join("; "))
}
