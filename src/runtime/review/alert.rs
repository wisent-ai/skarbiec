// `review --before <iso> --alert`: a scheduled security review whose
// findings reach the chat channel `alert set` names, so expiring
// certificates, unused grants and old passwords are seen without anyone
// running the review by hand. Each section is reduced as Desktop's Security
// review reduces it — the error a failed section carries, or how many rows
// each list in it holds — and only sections holding rows, or failing, are
// posted; a review that finds nothing posts nothing. The message names
// sections and counts, never an item's value.

use serde_json::{json, Value};

/// One section's rows: a list's length, or each list member of an object
/// with its length; None when it holds no rows.
fn found(value: &Value) -> Option<String> {
    match value {
        Value::Array(rows) if !rows.is_empty() => Some(format!("{} found", rows.len())),
        Value::Object(members) => {
            let lists: Vec<String> = members
                .iter()
                .filter_map(|(key, member)| {
                    member
                        .as_array()
                        .filter(|rows| !rows.is_empty())
                        .map(|rows| format!("{key}: {}", rows.len()))
                })
                .collect();
            (!lists.is_empty()).then(|| lists.join(", "))
        }
        _ => None,
    }
}

/// Post the review's findings when it holds any, answering whether it did.
pub(super) fn post(report: &Value) -> Value {
    let failed: Vec<&str> = report["failed_sections"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut lines: Vec<String> = report["sections"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(name, _)| !failed.contains(&name.as_str()))
        .filter_map(|(name, section)| found(section).map(|rows| format!("{name}: {rows}")))
        .collect();
    lines.extend(
        failed
            .iter()
            .map(|name| format!("{name} failed: {}", report["sections"][*name]["error"])),
    );
    if lines.is_empty() {
        return json!({"posted": false, "reason": "the review found nothing"});
    }
    let text = format!(
        "skarbiec review held to {}: {}",
        report["before"],
        lines.join("; ")
    );
    match crate::runtime::alert::send(&text) {
        Ok(Some(_)) => json!({"posted": true, "sections": lines.len()}),
        Ok(None) => json!({"posted": false, "reason": "no alert is set on this host"}),
        Err(error) => json!({"posted": false, "error": format!("{error:#}")}),
    }
}
