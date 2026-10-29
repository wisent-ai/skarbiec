// Whether every bindings file this host knows of (bindings list) still gives
// each program its value: a file an import wrote, or one remembered with
// `bindings remember`, fails the check when a line names an item in the
// trash, an id no item has, a field the item lacks, or the file is gone —
// the line `exec --env-from` would break on, found before a deploy does.

use serde_json::Value;

use super::super::{check, FAIL, NOT_CONFIGURED, PASS};

const NAME: &str = "bindings_files";

pub(in crate::runtime::doctor) fn bindings_files_check() -> Value {
    let files = match crate::runtime::bindings::known_report() {
        Ok(files) => files,
        Err(error) => return check(NAME, FAIL, format!("{error:#}")),
    };
    if files.is_empty() {
        return check(
            NAME,
            NOT_CONFIGURED,
            "this host knows of no bindings file; imports and bindings remember add them".into(),
        );
    }
    let problems: Vec<String> = files
        .iter()
        .filter(|file| file["ok"] != Value::Bool(true))
        .map(|file| match file["error"].as_str() {
            Some(error) => format!(
                "{}: {error}; bindings forget {} if it is gone for good",
                file["file"], file["file"]
            ),
            None => format!(
                "{}: {}",
                file["file"],
                file["failing"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|row| format!("{} — {}", row["variable"], row["problem"]))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        })
        .collect();
    match problems.is_empty() {
        true => check(
            NAME,
            PASS,
            format!(
                "every line of {} known bindings files gives its program a value",
                files.len()
            ),
        ),
        false => check(NAME, FAIL, problems.join("; ")),
    }
}
