// `skarbiec exec --env NAME=<id>:<field> [--env ...] -- <program> [args...]`:
// run one program with vault values in its environment, so a deploy script,
// a database client or a test run reads its credentials from variables while
// they never pass through a shell history, a file or this command's output.
// The values exist only in the child's environment; the journal records which
// item and field went into which variable and the program, never a value.
// The child inherits this terminal, and its exit status becomes this
// command's, so `skarbiec exec` stands in for the program in a script.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use crate::cli::args::Usage;
use crate::core::{vault::Vault, vault_path};

const USAGE: &str = "usage: exec (--env NAME=<id>:<field> | --env-item PREFIX=<id> | --env-tag <tag> | --env-from <file>) [...] -- <program> [args...]";

/// One variable the child gets: its name and the item field it holds.
pub(crate) struct Binding {
    pub(crate) name: String,
    pub(crate) item: String,
    pub(crate) field: String,
}

/// A variable name a shell can read back: a letter or underscore, then
/// letters, digits and underscores.
pub(crate) fn is_variable(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|rest| rest.is_ascii_alphanumeric() || rest == '_')
}

fn binding(given: &str) -> Result<Binding> {
    let refused = || Usage(format!("--env {given} is not NAME=<id>:<field>; {USAGE}"));
    let (name, source) = given.split_once('=').ok_or_else(refused)?;
    let (item, field) = source.rsplit_once(':').ok_or_else(refused)?;
    if !is_variable(name) {
        return Err(Usage(format!(
            "--env {given}: {name} is not a variable name; use letters, digits and underscores, not starting with a digit"
        ))
        .into());
    }
    if item.is_empty() || field.is_empty() {
        return Err(refused().into());
    }
    Ok(Binding {
        name: name.to_string(),
        item: item.to_string(),
        field: field.to_string(),
    })
}

/// The bindings a file lists, one NAME=<id>:<field> a line, so a project can
/// commit which variables its programs read and from where; blank lines and
/// lines starting with # are skipped, and a refusal quotes the line.
pub(crate) fn bindings_in(file: &str) -> Result<Vec<Binding>> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("read the bindings file {file}"))?;
    let mut listed = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        listed.push(binding(line).with_context(|| format!("{file}: the line `{line}`"))?);
    }
    if listed.is_empty() {
        return Err(Usage(format!("{file} lists no NAME=<id>:<field>; {USAGE}")).into());
    }
    Ok(listed)
}

/// Every text field of one item, each as PREFIX_FIELD in upper case — a
/// database login as DB_USERNAME and DB_PASSWORD — so a program that reads
/// the whole credential needs one option, not one per field.
fn item_bindings(given: &str) -> Result<Vec<Binding>> {
    let refused = || Usage(format!("--env-item {given} is not PREFIX=<id>; {USAGE}"));
    let (prefix, item) = given.split_once('=').ok_or_else(refused)?;
    if !is_variable(prefix) || item.is_empty() {
        return Err(refused().into());
    }
    let payload = Vault::open(vault_path())?.get_item(item)?;
    let fields = payload
        .get("fields")
        .and_then(Value::as_object)
        .with_context(|| format!("{item} holds no fields"))?;
    let listed: Vec<Binding> = fields
        .iter()
        .filter(|(_, value)| value.as_str().is_some_and(|text| !text.is_empty()))
        .map(|(field, _)| Binding {
            name: format!("{prefix}_{}", field.to_ascii_uppercase()),
            item: item.to_string(),
            field: field.clone(),
        })
        .collect();
    if listed.is_empty() {
        bail!("{item} holds no text field to put into the environment");
    }
    Ok(listed)
}

/// Every live item carrying a tag, each through `item_bindings` under its id
/// in upper case with every other character an underscore — prod-db as
/// PROD_DB_PASSWORD — so a project's whole set of credentials goes in by its
/// tag and an item added to the set later goes in too.
fn tag_bindings(tag: &str) -> Result<Vec<Binding>> {
    let tagged = crate::cli::bulk::carrying(&Vault::open(vault_path())?, tag, false);
    if tagged.is_empty() {
        bail!("no live item carries the tag {tag}, so nothing would go into the environment");
    }
    let mut listed = Vec::new();
    for id in &tagged {
        let prefix: String = id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect();
        if !is_variable(&prefix) {
            bail!("{id}, tagged {tag}, gives the prefix {prefix}, which is not a variable name; bind it with --env-item <PREFIX>={id}");
        }
        listed.extend(item_bindings(&format!("{prefix}={id}"))?);
    }
    Ok(listed)
}

/// The words before `--` are `--env` bindings, `--env-item` items and
/// `--env-from` files of bindings; the words after it are the program and its
/// arguments, passed on untouched so a flag of the program is never read as
/// one of this command.
fn parse(rest: &[String]) -> Result<(Vec<Binding>, String, Vec<String>)> {
    let no_program = || Usage(format!("name the program after --; {USAGE}"));
    let split = rest
        .iter()
        .position(|word| word == "--")
        .ok_or_else(no_program)?;
    let (ours, theirs) = rest.split_at(split);
    let mut bindings: Vec<Binding> = Vec::new();
    let mut words = ours.iter();
    while let Some(word) = words.next() {
        let (option, inline) = match word.split_once('=') {
            Some((option, value)) => (option, Some(value.to_string())),
            None => (word.as_str(), None),
        };
        let value = match inline {
            Some(value) => value,
            None => words
                .next()
                .cloned()
                .ok_or_else(|| Usage(format!("{option} needs a value; {USAGE}")))?,
        };
        let found = match option {
            "--env" => vec![binding(&value)?],
            "--env-from" => bindings_in(&value)?,
            "--env-item" => item_bindings(&value)?,
            "--env-tag" => tag_bindings(&value)?,
            _ => return Err(Usage(format!("{word} is not an option of exec; {USAGE}")).into()),
        };
        for next in found {
            if bindings.iter().any(|known| known.name == next.name) {
                return Err(Usage(format!(
                    "{} is bound twice; give each variable once",
                    next.name
                ))
                .into());
            }
            bindings.push(next);
        }
    }
    if bindings.is_empty() {
        return Err(Usage(format!(
            "exec puts at least one vault value into the program's environment; {USAGE}"
        ))
        .into());
    }
    // `theirs` starts with the `--` itself.
    let (_separator, command) = theirs.split_first().ok_or_else(no_program)?;
    let (program, arguments) = command.split_first().ok_or_else(no_program)?;
    Ok((bindings, program.clone(), arguments.to_vec()))
}

/// Runs the program with the bindings in its environment and ends this
/// process with the program's exit status. Every value is read before the
/// program starts, so a missing item or field starts nothing.
pub fn run(rest: &[String]) -> Result<()> {
    let (bindings, program, arguments) = parse(rest)?;
    let vault = Vault::open(vault_path())?;
    let mut command = Command::new(&program);
    command.args(&arguments);
    for binding in &bindings {
        let payload = vault.get_item(&binding.item)?;
        let fields = payload
            .get("fields")
            .and_then(Value::as_object)
            .with_context(|| format!("{} holds no fields", binding.item))?;
        let Some(value) = fields.get(&binding.field).and_then(Value::as_str) else {
            bail!(
                "{} has no text field {} for {}; its fields are: {}",
                binding.item,
                binding.field,
                binding.name,
                fields.keys().cloned().collect::<Vec<_>>().join(", ")
            );
        };
        command.env(&binding.name, value);
    }
    let journal: Vec<Value> = bindings
        .iter()
        .map(|binding| json!({"variable": binding.name, "item": binding.item, "field": binding.field}))
        .collect();
    crate::runtime::audit::append("exec", &json!({"program": program, "env": journal}))?;
    let status = stado_wait::blocking(
        stado_wait::Kind::Process,
        "a program run by skarbiec exec",
        &program,
        || command.status(),
    )
    .with_context(|| format!("start {program}"))?;
    match (status.code(), status.signal()) {
        (Some(code), _) => std::process::exit(code),
        (None, Some(signal)) => bail!("{program} was ended by signal {signal}"),
        (None, None) => bail!("{program} ended without an exit status: {status}"),
    }
}
