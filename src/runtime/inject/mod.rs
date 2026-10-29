// `skarbiec inject <template> <out-file> [--replace]`: write a configuration
// file a program reads — a .env, a database.yml, a kubeconfig — from a
// template that names where each secret comes from, so the template can be
// committed and only the filled copy, owner-only, holds values. A reference
// is `{{ skarbiec:<id>:<field> }}`; any other `{{ … }}` belongs to whatever
// else reads the template and is left as written. Every reference is read
// before anything is written, so a missing item or field writes no file.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use crate::cli::args::{flag_set, Usage};
use crate::core::{vault::Vault, vault_path};

const USAGE: &str = "usage: inject <template> <out-file> [--replace]";
const OPEN: &str = "{{";
const CLOSE: &str = "}}";
const SCHEME: &str = "skarbiec:";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "inject" {
        return Ok(None);
    }
    match positionals {
        [template, out] => {
            // The filled file is written beside itself and its directory
            // synced, so a bare file name is taken in the working directory;
            // the template is too, so the two compare as the same file.
            let here = std::env::current_dir().context("read the working directory")?;
            inject(&here.join(template), &here.join(out), flag_set(flags, "replace")).map(Some)
        }
        _ => Err(Usage(USAGE.to_string()).into()),
    }
}

/// One reference the template makes: its line, for a refusal, and the item
/// field it names.
struct Reference {
    line: usize,
    item: String,
    field: String,
}

/// The template cut into the text kept as written and the references filled.
enum Piece<'t> {
    Kept(std::borrow::Cow<'t, str>),
    Filled(Reference),
}

fn pieces(text: &str) -> Result<Vec<Piece<'_>>> {
    let mut found = Vec::new();
    let mut rest = text;
    loop {
        let Some((head, after_open)) = rest.split_once(OPEN) else { break };
        let Some((inner, after_close)) = after_open.split_once(CLOSE) else { break };
        // The line the reference starts on: the lines of everything before it.
        let line = text[..text.len() - rest.len() + head.len()].split('\n').count();
        found.push(Piece::Kept(head.into()));
        let written = inner;
        let inner = inner.trim();
        match inner.strip_prefix(SCHEME) {
            // Not ours: kept exactly as written, spaces and all.
            None => found.push(Piece::Kept(format!("{OPEN}{written}{CLOSE}").into())),
            Some(named) => {
                let Some((item, field)) =
                    named.rsplit_once(':').filter(|(item, field)| !item.is_empty() && !field.is_empty())
                else {
                    bail!("line {line}: {OPEN} {inner} {CLOSE} is not {OPEN} skarbiec:<id>:<field> {CLOSE}; nothing was written");
                };
                found.push(Piece::Filled(Reference { line, item: item.to_string(), field: field.to_string() }));
            }
        }
        rest = after_close;
    }
    found.push(Piece::Kept(rest.into()));
    Ok(found)
}

fn inject(template: &Path, out: &Path, replace: bool) -> Result<Value> {
    if template == out {
        return Err(Usage(format!("{} is the template itself; name another file to write", out.display())).into());
    }
    if crate::core::is_present(out, "the output file")? && !replace {
        bail!("{} exists; --replace overwrites it, else name a new file", out.display());
    }
    let text = std::fs::read_to_string(template).with_context(|| format!("read the template {}", template.display()))?;
    let cut = pieces(&text)?;
    let named: Vec<&Reference> = cut
        .iter()
        .filter_map(|piece| match piece {
            Piece::Filled(reference) => Some(reference),
            Piece::Kept(_) => None,
        })
        .collect();
    if named.is_empty() {
        bail!(
            "{} names no {OPEN} skarbiec:<id>:<field> {CLOSE}, so there is nothing to fill; nothing was written",
            template.display()
        );
    }
    let vault = Vault::open(vault_path())?;
    let mut filled = String::with_capacity(text.len());
    for piece in &cut {
        match piece {
            Piece::Kept(kept) => filled.push_str(kept),
            Piece::Filled(reference) => {
                let payload = vault
                    .get_item(&reference.item)
                    .with_context(|| format!("line {}: {}; nothing was written", reference.line, reference.item))?;
                let Some(value) =
                    payload.get("fields").and_then(|fields| fields.get(&reference.field)).and_then(Value::as_str)
                else {
                    bail!(
                        "line {}: {} has no text field {}; nothing was written",
                        reference.line,
                        reference.item,
                        reference.field
                    );
                };
                filled.push_str(value);
            }
        }
    }
    crate::core::vault::atomic_write(out, filled.as_bytes())
        .with_context(|| format!("write the filled file {}", out.display()))?;
    let listed: Vec<Value> = named
        .iter()
        .map(|reference| json!({"line": reference.line, "item": reference.item, "field": reference.field}))
        .collect();
    let record = json!({
        "template": template.display().to_string(),
        "out": out.display().to_string(),
        "references": listed,
    });
    crate::runtime::audit::append("inject", &record)?;
    let mut answer = record;
    answer["ok"] = json!(true);
    Ok(answer)
}
