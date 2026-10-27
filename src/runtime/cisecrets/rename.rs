// A renamed item stays bound in the CI and cluster targets this host keeps
// set: every bindings file a kept target is set from has each
// `NAME=<old id>:<field>` line rewritten to the new id, and the kept record
// remembers the item's revision under the new id, so the next maintain pass
// sets the same values and `doctor` finds nothing broken. A file that cannot
// be rewritten is named with why; the item is renamed already, so that does
// not refuse the rename.

use anyhow::Result;
use serde_json::{json, Value};

use crate::core::vault_path;

/// Rebind `from` to `to` in every kept target's bindings file, answering
/// the files moved and those that could not be, each with why.
pub(crate) fn follow_rename(from: &str, to: &str) -> Result<Value> {
    let store = super::kept::store(&vault_path());
    let mut entries = super::kept::read(&store)?;
    let mut moved: Vec<String> = Vec::new();
    let mut not_moved: Vec<Value> = Vec::new();
    for entry in entries.iter_mut() {
        if let Some(revision) = entry["revisions"].as_object_mut().and_then(|revisions| revisions.remove(from)) {
            entry["revisions"][to] = revision;
        }
        let Some(file) = entry["bindings"].as_str().map(str::to_string) else {
            continue;
        };
        if moved.contains(&file) {
            continue;
        }
        match crate::runtime::bindings::rebind_file(&file, from, to) {
            Ok(true) => moved.push(file),
            Ok(false) => {}
            Err(error) => not_moved.push(json!({"file": file, "error": format!("{error:#}")})),
        }
    }
    if !entries.is_empty() {
        super::kept::write(&store, &entries)?;
    }
    Ok(json!({"moved": moved, "not_moved": not_moved}))
}
