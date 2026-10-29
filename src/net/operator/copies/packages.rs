// The operator routes over developer tools' tokens and the bindings files
// they are read through. `tool/list`, `tool/status` and `tool/import` run
// `skarbiec tool` — the one operation that takes a tool's plain-text token
// into the vault, whichever tool's adapter — and `bindings/check`,
// `bindings/list`, `bindings/remember` and `bindings/forget` run `skarbiec
// bindings`. They read and write files on this machine, so they are
// host-local and never forwarded; the import and the two that change the
// list of known bindings files are mutations. The answers name tools,
// entries, variables and files, never a token.

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

use super::super::calls::{flags, optional, runtime, text};
use super::absolute;

/// Each `tool` route: the route, the leaf it runs, the flags it carries, and
/// whether it is the import, which changes the vault.
const TOOL: &[(&str, &str, &[&str], bool)] = &[
    ("/v1/operator/tool/list", "list", &[], false),
    ("/v1/operator/tool/status", "status", &[], false),
    (
        "/v1/operator/tool/import",
        "import",
        &["select", "tags"],
        true,
    ),
];
const CHECK: &str = "/v1/operator/bindings/check";
/// The routes over the bindings files this host knows of: each route, the
/// `bindings` leaf it runs, and whether it changes the list and takes file.
const KNOWN: &[(&str, &str, bool)] = &[
    ("/v1/operator/bindings/list", "list", false),
    ("/v1/operator/bindings/remember", "remember", true),
    ("/v1/operator/bindings/forget", "forget", true),
];

fn known(path: &str) -> Option<&'static (&'static str, &'static str, bool)> {
    KNOWN.iter().find(|(route, _, _)| *route == path)
}

fn tool_token(
    path: &str,
) -> Option<&'static (&'static str, &'static str, &'static [&'static str], bool)> {
    TOOL.iter().find(|(route, _, _, _)| *route == path)
}

pub(in crate::net::operator) fn is_mutation(path: &str) -> bool {
    tool_token(path).is_some_and(|(_, _, _, imports)| *imports)
        || known(path).is_some_and(|(_, _, changes)| *changes)
}

pub(in crate::net::operator) fn is_host_local(path: &str) -> bool {
    path == CHECK || known(path).is_some() || tool_token(path).is_some()
}

pub(super) fn answer(path: &str, parsed: &Value) -> Result<Option<Value>> {
    if path == CHECK {
        return runtime(
            "bindings",
            &flags(parsed, &["refuse"]),
            &["check".to_string(), absolute(parsed, "file")?],
        )
        .map(Some);
    }
    if let Some((_, leaf, changes)) = known(path) {
        let mut positionals = vec![leaf.to_string()];
        if *changes {
            positionals.push(absolute(parsed, "file")?);
        }
        return runtime("bindings", &flags(parsed, &[]), &positionals).map(Some);
    }
    let Some((_, leaf, carried, imports)) = tool_token(path) else {
        return Ok(None);
    };
    let mut given = flags(parsed, carried);
    let mut positionals = vec![leaf.to_string()];
    // status names a tool or none; the import names the tool, its item and
    // the bindings file, an absolute path on this machine.
    if *imports {
        given.extend(HashMap::from([(
            "bindings".to_string(),
            absolute(parsed, "bindings")?,
        )]));
        positionals.push(text(parsed, "tool")?);
        positionals.push(text(parsed, "id")?);
    } else {
        positionals.extend(optional(parsed, "tool"));
    }
    runtime("tool", &given, &positionals).map(Some)
}
