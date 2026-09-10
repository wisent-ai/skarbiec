// The capability-route table: the file half of declared route resolution.
//
// The table holds exactly what nothing declares. A provider credential and an
// agent signing identity are found from what the item itself says -- its
// `brama:provider:` and `brama:id:` tags, or an `internal-authority` item's
// own `id` and `agent_auth_secret` fields -- so no row has to be written for
// either, and renaming the item cannot move them. What is left is the resource
// vocabulary a vault item cannot express: `origin:<page origin>/<field class>`
// is a sign-in form's own name for itself, and only an operator can say which
// credential answers it.
//
// A hand-declared row names an exact id, which is the safe pattern in this
// product: rename the item and `route verify` says so, naming where it went.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;

use super::super::capability::{routes_path, write_private_file};
use crate::core::vault::Vault;
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

// A resource is the broker's own vocabulary and carries separators; an item and
// a field are vault names. The bounds are the ones `grant capability` already
// applies to a resource it refuses to issue.
pub(super) const MAX_RESOURCE_CHARS: usize = 512;
pub(super) const MAX_REASON_CHARS: usize = 512;

const STAMP_FORMAT: &str = "+%Y%m%dT%H%M%SZ";
const ISO_FORMAT: &str = "+%Y-%m-%dT%H:%M:%SZ";

/// Whether this host has a capability route table at all, and where.
///
/// A reader that must describe the table's absence rather than fail on it --
/// `doctor`, for which no table is `not_configured` and not an outage -- asks
/// this first.
pub(crate) fn table_path() -> std::path::PathBuf {
    routes_path()
}

/// Rows the items now declare for themselves.
///
/// Resolution never reads one, so it is neither broken nor in use: dead weight
/// an operator cannot otherwise see. Naming it is how a table written by the
/// deleted reconciliation gets emptied instead of quietly kept.
pub(super) fn shadowed(
    table: &Map<String, Value>,
    rows: &[super::declaration::Row],
) -> Vec<Value> {
    rows.iter()
        .filter(|row| row.declared_by != "table" && table.contains_key(&row.resource))
        .map(|row| json!({"resource": row.resource, "resolved_from": row.declared_by}))
        .collect()
}

/// The hand-declared rows, or an empty set.
///
/// Absence stopped being a refusal when resolution started reading the
/// declaration: a host whose every resource is declared by the items
/// themselves has no table at all and still resolves all of them. `route
/// resolve` reports the path anyway, so an operator can still see which file a
/// hand-declared row would be written to.
pub(super) fn load() -> Result<Map<String, Value>> {
    let path = routes_path();
    if !path.exists() {
        return Ok(Map::new());
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

/// One table row: the item and field it names, plus that item's `item_uid`
/// when the item has one. That is what lets verification distinguish a renamed
/// item from a purged one; a row without it degrades to naming only the name.
fn route_row(vault: &Vault, item: &str, field: &str) -> Value {
    let mut row = Map::new();
    row.insert("item".to_string(), json!(item));
    row.insert("field".to_string(), json!(field));
    if let Some(item_uid) = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(item))
        .and_then(crate::core::vault::entry_item_uid)
    {
        row.insert("item_uid".to_string(), json!(item_uid));
    }
    Value::Object(row)
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
/// A truncated write does not degrade one route, it stops every hand-declared
/// resource on the host from resolving. The previous table is kept under the
/// name the hand-run repair already used (`<table>.json.before-<stamp>`), so
/// the backups an operator already has and the ones this writes stay one
/// series.
fn publish(path: &Path, table: &Value) -> Result<Option<String>> {
    let mut backup = None;
    if path.exists() {
        let stamp = utc(STAMP_FORMAT);
        if stamp.is_empty() {
            bail!("refusing to write capability routes without a stamped backup name");
        }
        let mut copy = path.with_extension(format!("json.before-{stamp}"));
        // `date` on this platform stops at whole seconds, and two routes were
        // once declared inside one. The process id separates them, so the
        // second write cannot overwrite the snapshot the first took.
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
/// `SKARBIEC_AUDIT_FILE` points -- on this fleet the vault's directory, while
/// the table sits in the broker's -- and an operator who finds a route they do
/// not recognise is looking at the table.
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

/// Write one hand-declared row, with the sentence that explains it.
///
/// Idempotent: a row that already says exactly this is reported and nothing is
/// written, which is what makes the command safe to leave in a provisioning
/// sequence. A resource already mapped somewhere *else* is refused rather than
/// repointed: silently moving a live route -- the Apple login every trajectory
/// redeems, say -- costs more than the afternoon the unmapped Cloudflare login
/// already cost.
///
/// `reason` is not optional at the command boundary. This table decides which
/// credential a login form receives, so a change to it is never
/// self-explanatory later: the sentence travels into the journal beside the
/// table and into the hash-chained one.
pub(super) fn write_row(
    resource: &str,
    item: &str,
    field: &str,
    reason: &str,
    vault: Option<&Vault>,
) -> Result<Value> {
    let path = routes_path();
    let mut table = load()?;
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
                "declared": false,
                "resource": resource,
                "item": item,
                "field": field,
                "backup": Value::Null,
            }));
        }
        bail!(
            "capability route {resource} already maps {}#{}: repointing a live route is not a declaration",
            mapped("item"),
            mapped("field")
        );
    }
    // The item's uid beside its name, so verification can say where the item
    // went rather than only that the name stopped resolving. Opportunistic on
    // purpose: a row may be declared ahead of provisioning, so an unreadable
    // vault, an absent item or an item with no uid yet all leave the row
    // exactly as it would have been written before.
    let row = match vault {
        Some(vault) => route_row(vault, item, field),
        None => json!({"item": item, "field": field}),
    };
    table.insert(resource.to_string(), row);
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
    crate::runtime::audit::append_sync("capability-route-declared", &record)?;
    Ok(json!({
        "declared": true,
        "resource": resource,
        "item": item,
        "field": field,
        "backup": backup,
    }))
}
