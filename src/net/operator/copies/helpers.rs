// The operator routes over `skarbiec helper`: `helper/list`, `helper/status`,
// `helper/setup`, `helper/import` and `helper/unset`, one route per verb for
// every tool with an adapter. The body names the tool; its arguments and
// flags are the ones the tool's usage line declares for the verb, read by
// name from the body, and a flag that names a directory is taken only as an
// absolute path on this machine. Each tool's configuration is this machine's,
// so the routes are host-local and never forwarded; setup, import and unset
// are mutations. The answers name files, profiles, hosts and items, never a
// credential.

use anyhow::Result;
use serde_json::Value;

use super::super::calls::{flags, optional, runtime, text};
use super::absolute;

/// Each route, the `helper` verb it runs, and what it takes: Some(true) for
/// the verbs that change a tool's configuration and name the tool, Some(false)
/// for status, which names one tool or none, None for list.
const HELPER: &[(&str, &str, Option<bool>)] = &[
    ("/v1/operator/helper/list", "list", None),
    ("/v1/operator/helper/status", "status", Some(false)),
    ("/v1/operator/helper/setup", "setup", Some(true)),
    ("/v1/operator/helper/import", "import", Some(true)),
    ("/v1/operator/helper/unset", "unset", Some(true)),
];

fn route(path: &str) -> Option<&'static (&'static str, &'static str, Option<bool>)> {
    HELPER.iter().find(|(route, _, _)| *route == path)
}

pub(in crate::net::operator) fn is_mutation(path: &str) -> bool {
    route(path).is_some_and(|(_, _, takes)| *takes == Some(true))
}

pub(in crate::net::operator) fn is_host_local(path: &str) -> bool {
    route(path).is_some()
}

pub(super) fn answer(path: &str, parsed: &Value) -> Result<Option<Value>> {
    let Some((_, verb, takes)) = route(path) else {
        return Ok(None);
    };
    let mut positionals = vec![verb.to_string()];
    match takes {
        None => return runtime(crate::runtime::helper::COMMAND, &flags(parsed, &[]), &positionals).map(Some),
        Some(false) => {
            positionals.extend(optional(parsed, "tool"));
            return runtime(crate::runtime::helper::COMMAND, &flags(parsed, &[]), &positionals).map(Some);
        }
        Some(true) => {}
    }
    let tool = text(parsed, "tool")?;
    let takes = crate::runtime::helper::takes(&tool, verb)?;
    positionals.push(tool);
    for argument in &takes.arguments {
        positionals.push(text(parsed, argument)?);
    }
    let plain: Vec<&str> = takes.flags.iter().filter(|flag| !takes.directories.contains(flag)).map(String::as_str).collect();
    let mut given = flags(parsed, &plain);
    for directory in &takes.directories {
        if optional(parsed, directory).is_some() {
            given.insert(directory.clone(), absolute(parsed, directory)?);
        }
    }
    runtime(crate::runtime::helper::COMMAND, &given, &positionals).map(Some)
}
