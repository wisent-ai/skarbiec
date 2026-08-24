// Capability routes: the table where a workload's resource vocabulary meets the
// vault coordinates an operator authorised for it.
//
// The broker resolves `origin:<page origin>/<field class>` -- and every
// `provider:` and `agent:` resource -- by looking the resource up in this table
// and nowhere else (`access::capability`). Until now the table was edited by
// hand, and that is exactly how the Weles browser client reached the Cloudflare
// dashboard login, asked for the credential and was answered "Authentication
// credentials not available or invalid": the table carried the Apple equivalents
// and nothing for `origin:https://dash.cloudflare.com/email`, while the vault
// item `platform-admin-cloudflare` had held `username` and `password` the whole
// time. Nothing in the CLI could be asked which resources were mapped, so the
// gap was found by opening the file by hand.
//
// A hand-edited table fails the same way in the other direction: a route that
// names a field its item does not carry is indistinguishable from a working one
// until a login needs it, and then the refusal names neither the route nor the
// coordinate. So `list` resolves every route against the vault and prints what it
// found, and `verify` reports every route that cannot deliver -- never only the
// first -- and exits non-zero.
//
// The table maps names to coordinates and authorises nothing. Whether a workload
// may redeem a resource is decided at redemption by the live vault token that
// registers its Ed25519 workload key -- so the optional `<consumer>` argument
// here only narrows what is printed, and must never be read as a boundary.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;

use super::capability::{exact_token, routes_path, write_private_file};
use crate::core::{schema, vault::Vault, vault_path};
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

// A resource is the broker's own vocabulary and carries separators; an item and a
// field are vault names. The bounds are the ones `capability-issue` already
// applies to a resource it refuses to issue.
const MAX_RESOURCE_CHARS: usize = 512;
const MAX_NAME_CHARS: usize = 128;
const MAX_REASON_CHARS: usize = 512;
const ROUTED_PREFIXES: &[&str] = &["provider:", "agent:"];
const CREDENTIAL_FIELDS: &[&str] = &[
    "api_key",
    "token",
    "access_token",
    "apiKey",
    "key",
    "secret",
    "value",
];

const STAMP_FORMAT: &str = "+%Y%m%dT%H%M%SZ";
const ISO_FORMAT: &str = "+%Y-%m-%dT%H:%M:%SZ";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "routes" {
        return Ok(None);
    }
    let mut names = positionals.iter().map(String::as_str);
    let subcommand = names.next().unwrap_or("help");
    let consumer = names.next();
    let value = match subcommand {
        "list" => list(consumer)?,
        "add" => add(flags)?,
        "reconcile" => reconcile()?,
        "verify" => {
            let report = verify_report(consumer)?;
            let broken = report
                .get("broken")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let checked = report
                .get("checked")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            if !broken.is_empty() {
                println!("{}", serde_json::to_string_pretty(&report)?);
                let named: Vec<String> = broken
                    .iter()
                    .map(|entry| {
                        format!(
                            "{}: {}",
                            entry
                                .get("resource")
                                .and_then(Value::as_str)
                                .unwrap_or_default(),
                            entry
                                .get("problem")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                        )
                    })
                    .collect();
                bail!(
                    "{} of {} capability routes do not resolve: {}",
                    broken.len(),
                    checked,
                    named.join("; ")
                );
            }
            report
        }
        "help" => json!({
            "commands": [
                "routes list [<consumer>]",
                "routes add --resource <resource> --item <item> --field <field> --reason <text>",
                "routes reconcile",
                "routes verify [<consumer>]",
            ],
            "usage": "routes reconcile derives identity mappings for provider:* and agent:* items from the live vault; routes list [<consumer>] prints every route with the vault's answer for it; routes verify [<consumer>] exits non-zero when a route names a missing item or field; routes add is idempotent, keeps the previous table beside the new one, and requires --reason. The optional <consumer> argument matches resource text and is presentation only: it narrows what is printed and grants nothing, because redemption is authorised by the live vault token that registers a workload's Ed25519 key, never by this table.",
            "table": routes_path().display().to_string(),
        }),
        other => bail!("unknown routes command: {other}"),
    };
    Ok(Some(value))
}

/// One route as the vault answers it.
///
/// `problem` is the sentence `verify` prints. `list` prints only the two
/// booleans, because a desktop console renders them per row; the sentence is
/// what a human needs when the row is wrong.
struct Resolved<'a> {
    item: &'a str,
    field: &'a str,
    item_present: bool,
    field_present: bool,
    problem: Option<String>,
}

fn load() -> Result<Map<String, Value>> {
    let path = routes_path();
    // An absent table and an empty table produce the same refusal from the
    // broker and are entirely different repairs, so they are answered
    // differently here: absence is an error naming the file, emptiness lists no
    // routes.
    if !path.exists() {
        bail!(
            "no capability routes table at {}: every resource the broker is asked to resolve would map to nothing",
            path.display()
        );
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read capability routes {}", path.display()))?;
    let parsed: Value = serde_json::from_str(&raw)
        .with_context(|| format!("parse capability routes {}", path.display()))?;
    match parsed {
        Value::Object(table) => Ok(table),
        _ => bail!(
            "capability routes {} is not an object of resources",
            path.display()
        ),
    }
}

/// Presentation only. The argument narrows what is printed and authorises
/// nothing: a resource absent from this listing is refused because it has no
/// route, and a resource present in it is redeemed only by a workload whose key
/// a live vault token registers.
fn selected<'a>(
    table: &'a Map<String, Value>,
    consumer: Option<&'a str>,
) -> impl Iterator<Item = (&'a String, &'a Value)> {
    table
        .iter()
        .filter(move |(resource, _)| consumer.is_none_or(|needle| resource.contains(needle)))
}

/// Resolve one route the way redemption would, and say what stopped it.
///
/// `item_present` answers "can this host read this item at all" -- present in the
/// document, not in the trash, and it opened -- and `field_present` answers only
/// the field question, which it can never answer for an item that did not open.
/// Reporting an unopenable item as present used to leave both readers with one
/// sentence for two remedies: a desktop console rendering the live table saw ten
/// rows saying `item_present: true, field_present: false` on a host whose `gpg`
/// could not be spawned, which reads as ten items each missing the field named
/// beside it. It is now `item_present: false` for all ten, `verify` names the
/// cause once per item, and a false `field_present` under a true `item_present`
/// means exactly one thing: the item opened and does not carry that field.
///
/// Items are opened at most once per listing: a table maps several resources onto
/// one login item, and each open is a gpg process.
fn resolve<'a>(
    vault: &Vault,
    opened: &mut HashMap<String, Result<Value, String>>,
    resource: &str,
    entry: &'a Value,
) -> Resolved<'a> {
    let (Some(item), Some(field)) = (
        entry.get("item").and_then(Value::as_str),
        entry.get("field").and_then(Value::as_str),
    ) else {
        return Resolved {
            item: "",
            field: "",
            item_present: false,
            field_present: false,
            problem: Some(format!(
                "capability route for {resource} must name an item and a field"
            )),
        };
    };
    let stored = vault.doc().get("items").and_then(|items| items.get(item));
    let mut problem = match stored {
        None => Some(format!("no vault item {item}")),
        Some(record) if record.get("state").and_then(Value::as_str) == Some("trashed") => {
            Some(format!("vault item {item} is in trash"))
        }
        Some(_) => None,
    };
    let mut item_present = problem.is_none();
    let mut field_present = false;
    if item_present {
        let payload = opened
            .entry(item.to_string())
            .or_insert_with(|| vault.get_item(item).map_err(|error| error.to_string()));
        match payload {
            Err(detail) => {
                item_present = false;
                problem = Some(format!("vault item {item} does not open: {detail}"));
            }
            // Redemption hands out a text value and nothing else, so a field
            // holding an object -- `context`, say -- is as broken as a missing
            // one and is named separately rather than reported as absent.
            Ok(payload) => match schema::field(payload, field) {
                Err(_) => problem = Some(format!("vault item {item} has no {field} field")),
                Ok(value) if !value.is_string() => {
                    problem = Some(format!(
                        "vault item {item} field {field} is not a text value"
                    ))
                }
                Ok(_) => field_present = true,
            },
        }
    }
    Resolved {
        item,
        field,
        item_present,
        field_present,
        problem,
    }
}

/// Every route, with the vault's answer beside it.
///
/// The two booleans are the whole point of the command: the Cloudflare refusal
/// was a route away from working, and no surface said whether the coordinate it
/// named existed.
fn list(consumer: Option<&str>) -> Result<Value> {
    let table = load()?;
    let vault = Vault::open(vault_path())?;
    let mut opened = HashMap::new();
    let routes: Vec<Value> = selected(&table, consumer)
        .map(|(resource, entry)| {
            let row = resolve(&vault, &mut opened, resource, entry);
            json!({
                "resource": resource,
                "item": row.item,
                "field": row.field,
                "item_present": row.item_present,
                "field_present": row.field_present,
            })
        })
        .collect();
    Ok(json!({"consumer": consumer, "routes": routes}))
}

/// A flag that is absent, empty, or carrying a newline would land in the table
/// -- and in the audit line -- as something no later reader can split back out,
/// so every one is checked with the validator the broker applies to a resource
/// before it will issue a capability for it.
fn required<'a>(flags: &'a HashMap<String, String>, name: &str, max: usize) -> Result<&'a str> {
    let value = flags.get(name).map(String::as_str).unwrap_or_default();
    if !exact_token(value, max) {
        bail!("routes add requires an exact --{name}");
    }
    Ok(value)
}

fn utc(format: &str) -> String {
    Command::new("date")
        .args(["-u", format])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|text| text.trim().to_string())
        .unwrap_or_default()
}

/// Publish a table only after the bytes on disk parse back as one.
///
/// The broker holds no second copy: a truncated write does not degrade one
/// route, it stops every resource on the host from resolving. The previous table
/// is kept under the name the hand-run repair already used
/// (`<table>.json.before-<stamp>`), so the backups an operator already has and
/// the ones this writes stay one series.
fn publish(path: &Path, table: &Value) -> Result<Option<String>> {
    let mut backup = None;
    if path.exists() {
        let stamp = utc(STAMP_FORMAT);
        if stamp.is_empty() {
            bail!("refusing to write capability routes without a stamped backup name");
        }
        let mut copy = path.with_extension(format!("json.before-{stamp}"));
        // `date` on this platform stops at whole seconds, and the two Cloudflare
        // routes were added inside one second. A second add reusing the name
        // would overwrite the snapshot of the table as it stood before the
        // first, which is precisely the state a repair wants back, so the
        // process id separates them.
        if copy.exists() {
            copy = path.with_extension(format!("json.before-{stamp}-{}", std::process::id()));
        }
        fs::copy(path, &copy)
            .with_context(|| format!("back up capability routes to {}", copy.display()))?;
        backup = Some(copy.display().to_string());
    } else if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let staging = path.with_extension("json.staging");
    write_private_file(&staging, serde_json::to_string_pretty(table)?.as_bytes())?;
    let written = fs::read_to_string(&staging)
        .with_context(|| format!("re-read staged capability routes {}", staging.display()))?;
    serde_json::from_str::<Value>(&written).with_context(|| {
        format!(
            "staged capability routes {} do not parse",
            staging.display()
        )
    })?;
    fs::rename(&staging, path)
        .with_context(|| format!("install capability routes {}", path.display()))?;
    Ok(backup)
}

/// The reason, beside the table it explains.
///
/// The hash-chained journal stays the authority, but it lives wherever
/// `SKARBIEC_AUDIT_FILE` points -- on this fleet the vault's directory, while the
/// routes table sits in the broker's -- and an operator who finds a route they do
/// not recognise is looking at the table. One line per mutation next to the file
/// keeps "who added this, and why" answerable from that same directory.
fn append_beside(path: &Path, entry: &Value) -> Result<()> {
    let journal = path.with_extension("audit.jsonl");
    let mut line = serde_json::to_string(entry)?;
    line.push('\n');
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&journal)
        .with_context(|| format!("open {}", journal.display()))?
        .write_all(line.as_bytes())
        .with_context(|| format!("append {}", journal.display()))
}

/// Map one resource onto one vault field, without an editor.
///
/// Idempotent: a route that already says exactly this is reported and nothing is
/// written, which is what makes the command safe to leave in a provisioning
/// sequence. A resource already mapped somewhere *else* is refused rather than
/// repointed: the Cloudflare gap cost an afternoon, and silently moving a live
/// route -- the Apple login every trajectory redeems, say -- would cost more.
///
/// `--reason` is not optional. This table decides which credential a login form
/// receives, so a change to it is never self-explanatory later: the sentence
/// travels into the journal beside the table and into the hash-chained one, and
/// an add without it is refused before anything is read or written.
fn add(flags: &HashMap<String, String>) -> Result<Value> {
    let resource = required(flags, "resource", MAX_RESOURCE_CHARS)?;
    let item = required(flags, "item", MAX_NAME_CHARS)?;
    let field = required(flags, "field", MAX_NAME_CHARS)?;
    let reason = required(flags, "reason", MAX_REASON_CHARS)?;
    let path = routes_path();
    let mut table = if path.exists() { load()? } else { Map::new() };
    if let Some(existing) = table.get(resource) {
        let mapped = |name: &str| {
            existing
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        if mapped("item") == item && mapped("field") == field {
            return Ok(json!({
                "added": false,
                "resource": resource,
                "item": item,
                "field": field,
                "backup": Value::Null,
            }));
        }
        bail!(
            "capability route {resource} already maps {}#{}: repointing a live route is not an add",
            mapped("item"),
            mapped("field")
        );
    }
    table.insert(resource.to_string(), json!({"item": item, "field": field}));
    let backup = publish(&path, &Value::Object(table))?;
    let record = json!({
        "at": utc(ISO_FORMAT),
        "resource": resource,
        "item": item,
        "field": field,
        "reason": reason,
        "backup": backup,
    });
    append_beside(&path, &record)?;
    crate::runtime::audit::append_sync("capability-route-added", &record)?;
    Ok(json!({
        "added": true,
        "resource": resource,
        "item": item,
        "field": field,
        "backup": backup,
    }))
}
/// Derive the mappings whose resource and item are the same vault-owned name.
///
/// Provider and agent resources are minted from item ids, so these mappings
/// contain no operator choice: `provider:x` means the item named `provider:x`.
/// Skarbiec also owns the item schema and can select its credential field. An
/// item with no single credential field is reported and left untouched. Existing
/// routes are never repointed.
fn reconcile() -> Result<Value> {
    let path = routes_path();
    let mut table = if path.exists() { load()? } else { Map::new() };
    let vault = Vault::open(vault_path())?;
    let items = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .context("vault items section is not an object")?;
    let mut ids: Vec<&String> = items
        .iter()
        .filter(|(id, record)| {
            ROUTED_PREFIXES.iter().any(|prefix| id.starts_with(prefix))
                && record.get("state").and_then(Value::as_str) != Some("trashed")
        })
        .map(|(id, _)| id)
        .collect();
    ids.sort();

    let mut added = Vec::new();
    let mut skipped = Vec::new();
    for id in ids {
        if table.contains_key(id) {
            continue;
        }
        let payload = match vault.get_item(id) {
            Ok(payload) => payload,
            Err(error) => {
                skipped.push(json!({"resource": id, "problem": error.to_string()}));
                continue;
            }
        };
        let Some(fields) = payload.get("fields").and_then(Value::as_object) else {
            skipped.push(json!({"resource": id, "problem": "item carries no fields object"}));
            continue;
        };
        let candidates: Vec<&str> = CREDENTIAL_FIELDS
            .iter()
            .copied()
            .filter(|name| fields.get(*name).is_some_and(Value::is_string))
            .collect();
        let [field] = candidates.as_slice() else {
            skipped.push(json!({
                "resource": id,
                "problem": format!("item has {} credential fields: {}", candidates.len(), candidates.join(", ")),
            }));
            continue;
        };
        table.insert(id.clone(), json!({"item": id, "field": field}));
        added.push(json!({"resource": id, "item": id, "field": field}));
    }
    // A provider family resource names its unique primary credential. The
    // provider is the second colon-delimited component; subscription item ids
    // keep that prefix and mark the operator-selected default with `-primary`.
    // Multiple primaries are ambiguous and remain unmapped.
    let mut primaries: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for (resource, entry) in &table {
        let mut parts = resource.splitn(3, ':');
        if parts.next() != Some("provider") {
            continue;
        }
        let Some(provider) = parts.next() else {
            continue;
        };
        if parts.next().is_none() || !resource.ends_with("-primary") {
            continue;
        }
        if let (Some(item), Some(field)) = (
            entry.get("item").and_then(Value::as_str),
            entry.get("field").and_then(Value::as_str),
        ) {
            primaries
                .entry(format!("provider:{provider}"))
                .or_default()
                .push((item.to_string(), field.to_string()));
        }
    }
    for (resource, candidates) in primaries {
        if table.contains_key(&resource) {
            continue;
        }
        let [(item, field)] = candidates.as_slice() else {
            skipped.push(json!({
                "resource": resource,
                "problem": format!("provider has {} primary credentials", candidates.len()),
            }));
            continue;
        };
        table.insert(resource.clone(), json!({"item": item, "field": field}));
        added.push(json!({"resource": resource, "item": item, "field": field}));
    }

    let backup = if added.is_empty() {
        None
    } else {
        publish(&path, &Value::Object(table))?
    };
    if !added.is_empty() {
        let record = json!({
            "at": utc(ISO_FORMAT),
            "operation": "reconcile",
            "added": added,
            "backup": backup,
        });
        append_beside(&path, &record)?;
        crate::runtime::audit::append_sync("capability-routes-reconciled", &record)?;
    }
    Ok(json!({"added": added, "skipped": skipped, "backup": backup}))
}

/// Refuse a table that cannot deliver what it promises.
///
/// The report goes to stdout even when the command fails, because both readers
/// matter: a console shows the rows, a provisioning sequence reads the exit
/// status. Nothing here restarts, deletes, or cycles anything -- it is safe
/// against a live broker.
/// The verification report, always returned: which routes were checked and
/// which refuse, in the backend's own words. The command path turns a
/// non-empty `broken` into a non-zero exit after printing this document;
/// the loopback operator API answers with it, because the console reading it
/// over HTTP came for exactly the rows a bare exit status would throw away.
pub(crate) fn verify_report(consumer: Option<&str>) -> Result<Value> {
    let table = load()?;
    let vault = Vault::open(vault_path())?;
    let mut opened = HashMap::new();
    let rows: Vec<(&String, Option<String>)> = selected(&table, consumer)
        .map(|(resource, entry)| {
            (
                resource,
                resolve(&vault, &mut opened, resource, entry).problem,
            )
        })
        .collect();
    let broken: Vec<(&String, &String)> = rows
        .iter()
        .filter_map(|(resource, problem)| problem.as_ref().map(|problem| (*resource, problem)))
        .collect();
    Ok(json!({
        "checked": rows.len(),
        "broken": broken
            .iter()
            .map(|(resource, problem)| json!({"resource": resource, "problem": problem}))
            .collect::<Vec<Value>>(),
    }))
}
