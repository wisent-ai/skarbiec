// Whether the CI and cluster secrets this host keeps set are current. Each
// target `ci keep` recorded is set again by maintain once an item it
// names changes; a target still behind its items means maintain has not run
// since a rotation, or ran and could not set it — CI then deploys with a
// value the vault no longer holds. Bindings that cannot be read are named
// too, and so is a binding line naming an item trashed, renamed away or
// lacking the field, as `bindings check` names it: maintain could not set it.

use serde_json::Value;

use super::super::{check, FAIL, NOT_CONFIGURED, PASS};

const NAME: &str = "ci_secrets";

pub(in crate::runtime::doctor) fn ci_secrets_check() -> Value {
    let kept = match crate::runtime::cisecrets::kept_list() {
        Ok(kept) => kept,
        Err(error) => return check(NAME, FAIL, format!("{error:#}")),
    };
    let Some(targets) = kept["kept"]
        .as_array()
        .filter(|targets| !targets.is_empty())
    else {
        return check(
            NAME,
            NOT_CONFIGURED,
            "this host keeps no CI or cluster secrets set".into(),
        );
    };
    let mut problems = Vec::new();
    for target in targets {
        let named = format!("{} {}", target["target"], target["place"]);
        if let Some(error) = target["error"].as_str() {
            problems.push(format!("{named}: {error}"));
            continue;
        }
        let changed: Vec<&str> = target["changed_since"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if !changed.is_empty() {
            problems.push(format!(
                "{named} is behind {}; skarbiec maintain sets it again, and its failure names why it did not",
                changed.join(", ")
            ));
        }
        // The bindings file a kept target is set from, line by line.
        if let Some(file) = target["bindings"].as_str() {
            match crate::runtime::bindings::rows(file) {
                Err(error) => problems.push(format!("{named}: {error:#}")),
                Ok(rows) => {
                    for row in rows
                        .iter()
                        .filter(|row| row["ok"] == serde_json::json!(false))
                    {
                        problems.push(format!(
                            "{named}: {} from {file} gets nothing — {}",
                            row["variable"], row["problem"]
                        ));
                    }
                }
            }
        }
    }
    if problems.is_empty() {
        return check(
            NAME,
            PASS,
            format!(
                "{} kept targets hold every item's current value",
                targets.len()
            ),
        );
    }
    check(NAME, FAIL, problems.join("; "))
}
