// `skarbiec tool list | status [<tool>] | import <tool> <id> [--select
// <entry>] --bindings <file> [--tags <tag,...>]`: the one operation over a
// developer tool's token kept in plain text in that tool's own file. Every
// tool here reads its token from an environment variable before its file,
// so import stores the token as an item, binds the variable in the bindings
// file `exec --env-from` reads, remembers that file, and only then takes the
// token out of the tool's file; `skarbiec exec --env-from <file> --
// <program>` signs the tool in from the vault. Each tool is an adapter
// below — where its file is, how an entry is named, which variables it reads
// — and a tool is added by adding an adapter, never a command. status names
// each entry and how it is kept, with the import that moves a plain-text
// one; never a token. Every adapter answers an import with item, entry,
// variables, file and bindings, and this module journals it as
// tool-imported.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use crate::cli::args::{OrUsage, Usage};

const USAGE: &str = "usage: tool list | tool status [<tool>] | tool import <tool> <id> [--select <entry>] --bindings <file> [--tags <tag,...>]";
const PLAIN: &str = "plain text";

/// One import as the adapters take it.
pub(crate) struct Request<'a> {
    pub(crate) id: &'a str,
    pub(crate) select: Option<&'a str>,
    pub(crate) bindings: &'a Path,
    pub(crate) tags: Option<&'a String>,
}

impl Request<'_> {
    /// The entry --select names, refused naming what the tool keeps one
    /// token per when it is missing.
    pub(crate) fn selected(&self, what: &str) -> Result<&str> {
        self.select.with_context(|| format!("--select is needed: this tool keeps one token per {what}, and `skarbiec tool status` lists them"))
    }
}

/// How a tool's entries are chosen on import.
#[derive(Clone, Copy)]
enum Select {
    /// One token per entry: --select names the entry.
    Required(&'static str),
    /// One active token and named others: --select names another.
    Optional(&'static str),
    /// One token: --select is refused.
    Refused,
}

struct Adapter {
    tool: &'static str,
    /// What the tool is and where it keeps the token, for `tools`.
    about: &'static str,
    select: Select,
    status: fn() -> Result<Value>,
    import: fn(&Request) -> Result<Value>,
}

const ADAPTERS: &[Adapter] = &[
    Adapter {
        tool: "npm",
        about: "npm; .npmrc, one _authToken per registry",
        select: Select::Required("registry"),
        status: crate::runtime::npmcred::status,
        import: crate::runtime::npmcred::import,
    },
    Adapter {
        tool: "twine",
        about: "twine (PyPI uploads); ~/.pypirc, one password per repository section",
        select: Select::Required("repository"),
        status: crate::runtime::pypicred::status,
        import: crate::runtime::pypicred::import,
    },
    Adapter {
        tool: "gh",
        about: "the GitHub CLI; hosts.yml, one oauth_token per host",
        select: Select::Required("host"),
        status: crate::runtime::ghcred::status,
        import: crate::runtime::ghcred::import,
    },
    Adapter {
        tool: "gem",
        about: "gem push (RubyGems); gem's credentials, one key per gem server",
        select: Select::Required("key"),
        status: crate::runtime::gemcred::status,
        import: crate::runtime::gemcred::import,
    },
    Adapter {
        tool: "huggingface",
        about: "the Hugging Face libraries and hf CLI; the active token and named stored tokens",
        select: Select::Optional("stored token"),
        status: crate::runtime::hfcred::status,
        import: crate::runtime::hfcred::import,
    },
    Adapter {
        tool: "fly",
        about: "flyctl; config.yml's access_token",
        select: Select::Refused,
        status: crate::runtime::flycred::status,
        import: crate::runtime::flycred::import,
    },
    Adapter {
        tool: "vercel",
        about: "the Vercel CLI; auth.json's token",
        select: Select::Refused,
        status: crate::runtime::vercelcred::status,
        import: crate::runtime::vercelcred::import,
    },
];

fn names() -> String {
    ADAPTERS
        .iter()
        .map(|adapter| adapter.tool)
        .collect::<Vec<_>>()
        .join(", ")
}

fn adapter(tool: &str) -> Result<&'static Adapter> {
    match ADAPTERS.iter().find(|adapter| adapter.tool == tool) {
        Some(adapter) => Ok(adapter),
        None => Err(Usage(format!(
            "{tool} is not a tool this vault moves tokens for; it moves them for {}",
            names()
        ))
        .into()),
    }
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "tool" {
        return Ok(None);
    }
    match positionals {
        [leaf] if leaf == "list" => Ok(Some(tools())),
        [leaf] if leaf == "status" => Ok(Some(json!({"tools": status_all()}))),
        [leaf, tool] if leaf == "status" => status(adapter(tool)?).map(Some),
        [leaf, tool, id] if leaf == "import" => {
            let adapter = adapter(tool)?;
            let select = flags.get("select").map(String::as_str);
            if let (Select::Refused, Some(given)) = (adapter.select, select) {
                return Err(Usage(format!(
                    "--select {given}: {} keeps one token, so there is nothing to select",
                    adapter.tool
                ))
                .into());
            }
            let bindings = flags.get("bindings").or_usage(USAGE)?;
            let here = std::env::current_dir().context("read the working directory")?;
            let shown = here.join(bindings);
            let request = Request {
                id,
                select,
                bindings: &shown,
                tags: flags.get("tags"),
            };
            let mut answer = (adapter.import)(&request)?;
            answer["tool"] = json!(adapter.tool);
            crate::runtime::audit::append(
                "tool-imported",
                &json!({
                    "tool": adapter.tool,
                    "item": answer["item"],
                    "entry": answer["entry"],
                    "variables": answer["variables"],
                    "file": answer["file"],
                    "bindings": answer["bindings"],
                }),
            )?;
            Ok(Some(answer))
        }
        _ => Err(Usage(USAGE.to_string()).into()),
    }
}

fn tools() -> Value {
    let listed: Vec<Value> = ADAPTERS
        .iter()
        .map(|adapter| {
            let select = match adapter.select {
                Select::Required(what) => json!({"required": true, "names": what}),
                Select::Optional(what) => json!({"required": false, "names": what}),
                Select::Refused => Value::Null,
            };
            json!({"tool": adapter.tool, "about": adapter.about, "select": select})
        })
        .collect();
    json!({"tools": listed})
}

/// The import that moves one plain-text entry, as it would be typed: the
/// entry is selected unless the tool keeps one token, or it is the active
/// one of a tool with named others.
fn move_with(adapter: &Adapter, entry: &str, selected: bool) -> String {
    match (adapter.select, selected) {
        (Select::Refused, _) | (Select::Optional(_), false) => format!(
            "skarbiec tool import {} <id> --bindings <file>",
            adapter.tool
        ),
        _ => format!(
            "skarbiec tool import {} <id> --select {entry} --bindings <file>",
            adapter.tool
        ),
    }
}

/// One tool's status: the adapter's file and entries, each plain-text one
/// with the import that moves it. An adapter marks an entry not chosen by
/// --select with `"selected": false`.
fn status(adapter: &Adapter) -> Result<Value> {
    let mut answer = (adapter.status)()?;
    answer["tool"] = json!(adapter.tool);
    let entries = answer["entries"]
        .as_array_mut()
        .with_context(|| format!("the {} adapter answered no entries", adapter.tool))?;
    for entry in entries.iter_mut() {
        if entry["kept"] == PLAIN {
            let name = entry["entry"]
                .as_str()
                .with_context(|| {
                    format!(
                        "the {} adapter answered an entry without its name",
                        adapter.tool
                    )
                })?
                .to_string();
            let selected = entry["selected"] != json!(false);
            entry["move_with"] = json!(move_with(adapter, &name, selected));
        }
    }
    Ok(answer)
}

/// Every tool's status; a tool whose file cannot be read answers its error,
/// so one broken file does not hide the others.
pub(crate) fn status_all() -> Vec<Value> {
    ADAPTERS
        .iter()
        .map(|adapter| match status(adapter) {
            Ok(answer) => answer,
            Err(error) => json!({"tool": adapter.tool, "error": format!("{error:#}")}),
        })
        .collect()
}
