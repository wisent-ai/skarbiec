// `skarbiec helper list | status [<tool>] | setup|import|unset <tool> ... |
// answer <tool> ...`: the one operation that lets a tool on this machine read
// its credentials from the vault each time it needs them, for every tool with
// an adapter — the AWS CLI's credential_process, kubectl's exec plugin,
// Terraform's credentials helper, Cargo's credential provider, git's
// credential helper and Docker's credential helper. setup points the tool at
// this binary, import moves a credential the tool keeps in plain text into a
// new item and sets it up, unset stops it, and status says which tools ask
// this vault and what still sits in plain text. Each tool's arguments and
// flags are its adapter's usage line, so the CLI, the operator routes and
// `helper list` read them from one place.
//
// `answer` is the tool's side: the configuration setup writes runs
// `skarbiec helper answer <tool> ...`, and the tool reads the answer in its
// own protocol on standard output, never as this binary's JSON. Docker and
// Terraform run a program by a name of their own, linked to this binary;
// main hands those names to the same adapters.

use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::Usage;

/// The command, and the verb a tool's configuration runs.
pub(crate) const COMMAND: &str = "helper";
pub(crate) const ANSWER: &str = "answer";
const USAGE: &str = "usage: helper list | helper status [<tool>] | helper setup|import|unset <tool> [that tool's arguments] | helper answer <tool> [that tool's protocol]; `skarbiec helper list` names the tools and what each takes";
/// How every adapter's usage line opens, before its forms.
const USAGE_OPENING: &str = "usage: ";
/// The placeholder a usage line gives a flag naming a directory on this
/// machine, which the operator routes take only as an absolute path.
const DIRECTORY: &str = "<dir>";

struct Adapter {
    name: &'static str,
    about: &'static str,
    usage: &'static str,
    /// setup, import and unset: the verb first, then the tool's arguments.
    person: fn(&HashMap<String, String>, &[String]) -> Result<Value>,
    /// The tool's protocol, answered on standard output.
    answer: fn(&HashMap<String, String>, &[String]) -> Result<()>,
    status: fn() -> Result<Value>,
}

const ADAPTERS: &[Adapter] = &[
    Adapter {
        name: crate::runtime::awscred::TOOL,
        about: "the AWS CLI and every AWS SDK, through a profile's credential_process, from an access-key item",
        usage: crate::runtime::awscred::USAGE,
        person: crate::runtime::awscred::person,
        answer: crate::runtime::awscred::answer,
        status: crate::runtime::awscred::status,
    },
    Adapter {
        name: crate::runtime::kubecred::TOOL,
        about: "kubectl, helm and every client-go program, through a kubeconfig user's exec plugin, from a token or certificate item",
        usage: crate::runtime::kubecred::USAGE,
        person: crate::runtime::kubecred::person,
        answer: crate::runtime::kubecred::answer,
        status: crate::runtime::kubecred::status,
    },
    Adapter {
        name: crate::runtime::tfcred::TOOL,
        about: "Terraform's HCP Terraform, Terraform Enterprise and private registry tokens, through its credentials helper, from the login offered on the host",
        usage: crate::runtime::tfcred::USAGE,
        person: crate::runtime::tfcred::person,
        answer: crate::runtime::tfcred::answer,
        status: crate::runtime::tfcred::status,
    },
    Adapter {
        name: crate::runtime::cargocred::TOOL,
        about: "cargo publish, owner and yank, through Cargo's token-from-stdout provider, from the login offered on the registry's index host",
        usage: crate::runtime::cargocred::USAGE,
        person: crate::runtime::cargocred::person,
        answer: crate::runtime::cargocred::answer,
        status: crate::runtime::cargocred::status,
    },
    Adapter {
        name: crate::runtime::gitcred::TOOL,
        about: "git over https, through its credential helper for one forge host, from the login offered on the host",
        usage: crate::runtime::gitcred::USAGE,
        person: crate::runtime::gitcred::person,
        answer: crate::runtime::gitcred::answer,
        status: crate::runtime::gitcred::status,
    },
    Adapter {
        name: crate::runtime::dockercred::TOOL,
        about: "docker pull and push, through its credential helper for one registry, from the login offered on the registry",
        usage: crate::runtime::dockercred::USAGE,
        person: crate::runtime::dockercred::person,
        answer: crate::runtime::dockercred::answer,
        status: crate::runtime::dockercred::status,
    },
];

/// The words a tool's configuration runs after this binary's path, so its
/// request reaches the tool's adapter.
pub(crate) fn invocation(tool: &str) -> String {
    format!("{COMMAND} {ANSWER} {tool}")
}

/// What follows the invocation for `tool` in `words`; None when the words are
/// not this vault's invocation for it.
pub(crate) fn invoked<'a, 'b>(tool: &str, words: &'a [&'b str]) -> Option<&'a [&'b str]> {
    match words {
        [command, answer, named, rest @ ..] if *command == COMMAND && *answer == ANSWER && *named == tool => Some(rest),
        _ => None,
    }
}

fn names() -> String {
    ADAPTERS.iter().map(|adapter| adapter.name).collect::<Vec<_>>().join(", ")
}

fn adapter(name: &str) -> Result<&'static Adapter> {
    match ADAPTERS.iter().find(|adapter| adapter.name == name) {
        Some(adapter) => Ok(adapter),
        None => Err(Usage(format!("{name} is not a tool skarbiec answers for; it answers for {}", names())).into()),
    }
}

/// How one verb's form opens for one tool: `helper <verb> <tool>`.
fn opening(adapter: &Adapter, verb: &str) -> String {
    format!("{COMMAND} {verb} {}", adapter.name)
}

/// The part of an adapter's usage for one verb.
fn form(adapter: &'static Adapter, verb: &str) -> Result<&'static str> {
    let opening = opening(adapter, verb);
    let Some(parts) = adapter.usage.strip_prefix(USAGE_OPENING) else {
        bail!("{}'s usage line does not open with `{USAGE_OPENING}`, so its forms cannot be read: {}", adapter.name, adapter.usage);
    };
    match parts.split(" | ").find(|part| part.starts_with(&opening)) {
        Some(form) => Ok(form),
        None => Err(Usage(format!("helper {verb} has no form for {}; {}", adapter.name, adapter.usage)).into()),
    }
}

/// What one verb takes for one tool, read from the adapter's usage line: the
/// arguments written `<name>` after the tool, the flags, and the flags whose
/// value is a directory on this machine.
pub(crate) struct Takes {
    pub(crate) arguments: Vec<String>,
    pub(crate) flags: Vec<String>,
    pub(crate) directories: Vec<String>,
}

pub(crate) fn takes(tool: &str, verb: &str) -> Result<Takes> {
    let adapter = adapter(tool)?;
    let form = form(adapter, verb)?;
    let Some(after) = form.strip_prefix(opening(adapter, verb).as_str()) else {
        bail!("{tool}'s form for {verb} does not open with `{}`: {form}", opening(adapter, verb));
    };
    let words: Vec<&str> = after.split_whitespace().collect();
    let arguments = words
        .iter()
        .take_while(|word| word.starts_with('<'))
        .map(|word| word.trim_start_matches('<').trim_end_matches('>').to_string())
        .collect();
    let mut directories = Vec::new();
    let mut previous: Option<&str> = None;
    for word in &words {
        if *word == DIRECTORY {
            if let Some(flag) = previous.and_then(|flag| flag.strip_prefix("--")) {
                directories.push(flag.to_string());
            }
        }
        previous = Some(word);
    }
    Ok(Takes { arguments, flags: crate::cli::help::flags_in(form), directories })
}

fn list() -> Value {
    let tools: Vec<Value> = ADAPTERS
        .iter()
        .map(|adapter| json!({"tool": adapter.name, "about": adapter.about, "usage": adapter.usage}))
        .collect();
    json!({"tools": tools})
}

/// Every tool's state, or one tool's: which configuration asks this vault,
/// whether the program it runs is still there, and what still sits in plain
/// text. A tool whose state cannot be read is named with why.
fn status(only: Option<&String>) -> Result<Value> {
    let chosen: Vec<&Adapter> = match only {
        Some(name) => vec![adapter(name)?],
        None => ADAPTERS.iter().collect(),
    };
    let tools: Vec<Value> = chosen
        .iter()
        .map(|adapter| match (adapter.status)() {
            Ok(state) => json!({"tool": adapter.name, "state": state}),
            Err(error) => json!({"tool": adapter.name, "error": format!("{error:#}")}),
        })
        .collect();
    Ok(json!({"tools": tools}))
}

/// Every tool's state, for the MCP tool that says which tools read the vault.
pub(crate) fn status_all() -> Value {
    match status(None) {
        Ok(state) => state,
        Err(error) => json!({"error": format!("{error:#}")}),
    }
}

/// setup, import or unset for one tool, refusing a flag its form does not
/// take before the adapter runs.
fn person(verb: &str, flags: &HashMap<String, String>, rest: &[String]) -> Result<Value> {
    let Some((tool, arguments)) = rest.split_first() else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let adapter = adapter(tool)?;
    let taken = takes(tool, verb)?;
    if let Some(stray) = flags.keys().find(|key| !taken.flags.contains(key)) {
        return Err(Usage(format!("helper {verb} {tool} takes no --{stray}; {}", form(adapter, verb)?)).into());
    }
    let mut positionals = vec![verb.to_string()];
    positionals.extend(arguments.iter().cloned());
    let mut answer = (adapter.person)(flags, &positionals)?;
    answer["tool"] = json!(adapter.name);
    Ok(answer)
}

/// The person's side, answered as JSON; the operator routes reach it here.
/// `answer` is refused, since only the tool reads its protocol.
pub fn dispatch(command: &str, flags: &HashMap<String, String>, positionals: &[String]) -> Result<Option<Value>> {
    if command != COMMAND {
        return Ok(None);
    }
    let Some((verb, rest)) = positionals.split_first() else {
        return Ok(Some(list()));
    };
    match (verb.as_str(), rest) {
        ("list", []) => Ok(Some(list())),
        ("status", []) => status(None).map(Some),
        ("status", [tool]) => status(Some(tool)).map(Some),
        (ANSWER, _) => Err(Usage(format!("helper answer is a tool's protocol, answered on standard output in the tool's own words to the tool that runs it; {USAGE}")).into()),
        _ => person(verb, flags, rest).map(Some),
    }
}

/// `skarbiec helper ...` from main: the tool's protocol is answered on
/// standard output already and gives None; everything else is JSON.
pub fn command(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Option<Value>> {
    match positionals {
        [verb, tool, rest @ ..] if verb == ANSWER => {
            (adapter(tool)?.answer)(flags, rest)?;
            Ok(None)
        }
        _ => dispatch(COMMAND, flags, positionals),
    }
}
