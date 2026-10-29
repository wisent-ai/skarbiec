// Whether a developer tool on this machine still keeps a publishing or CLI
// token in plain text in its own file — every tool `skarbiec tool` has an
// adapter for. Each tool's status reads its file; a token any of them still
// holds fails the check with the import that moves it into the vault, so a
// token that publishes packages is not left on disk by someone who moved
// only the first one. A file that cannot be read fails it naming why; no
// tool keeping a sign-in at all is not configured.

use serde_json::Value;

use super::super::{check, FAIL, NOT_CONFIGURED, PASS};

const NAME: &str = "developer_tokens";
const PLAIN: &str = "plain text";

pub(in crate::runtime::doctor) fn developer_tokens_check() -> Value {
    let mut plain: Vec<String> = Vec::new();
    let mut unread: Vec<String> = Vec::new();
    let mut files = std::iter::empty::<()>().count();
    for answer in crate::runtime::tooltoken::status_all() {
        let tool = answer["tool"].as_str().map(str::to_string);
        if let Some(error) = answer["error"].as_str() {
            unread.push(format!("{tool:?}: {error}"));
            continue;
        }
        let file = answer["file"].as_str().map(str::to_string);
        let entries: Vec<&Value> = answer["entries"].as_array().into_iter().flatten().collect();
        if !entries.is_empty() {
            files += std::iter::once(()).count();
        }
        for entry in entries.into_iter().filter(|entry| entry["kept"] == PLAIN) {
            let move_with = entry["move_with"].as_str().map(str::to_string);
            match (file.as_deref(), move_with) {
                (Some(file), Some(move_with)) => plain.push(format!("{file}: {move_with}")),
                (_, move_with) => unread.push(format!("tool status for {tool:?} names a plain-text token without its file or import: {move_with:?}")),
            }
        }
    }
    let mut problems = unread;
    if !plain.is_empty() {
        problems.push(format!(
            "tokens still kept in plain text, each moved into the vault by — {}",
            plain.join("; ")
        ));
    }
    match (problems.is_empty(), files) {
        (false, _) => check(NAME, FAIL, problems.join("; ")),
        (true, found) if found == std::iter::empty::<()>().count() => check(
            NAME,
            NOT_CONFIGURED,
            "no developer tool `skarbiec tool` knows keeps a token in a file here".into(),
        ),
        (true, found) => check(
            NAME,
            PASS,
            format!("{found} developer tool files hold no token in plain text"),
        ),
    }
}
