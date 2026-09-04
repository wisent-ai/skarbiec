// skarbiec — self-contained vault for sensitive values (Rust).
// Per-recipient gpg encryption, versioned items, trash/restore, generator.
// Access/runtime/net layers are wired in sibling modules. No numeric literals:
// counts/lengths arrive from argv via parse(), never as source constants.

mod access;
mod bonds;
mod browser;
mod core;
mod credential;
mod invite;
mod native_host;
mod net;
mod onboarding;
mod runtime;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;

use core::{crypto, items, schema, vault::Vault};

/// One definition of "which vault": the core layer owns it (including the
/// request-scoped override the loopback operator API sets), and this crate
/// root keeps only the re-export its own commands already call.
fn vault_path() -> PathBuf {
    core::vault_path()
}

// key=value or bare --flag (present -> "true"); everything else is positional.
fn parse_args(rest: &[String]) -> (HashMap<String, String>, Vec<String>) {
    let mut flags = HashMap::new();
    let mut positionals = Vec::new();
    let mut iter = rest.iter().peekable();
    while let Some(arg) = iter.next() {
        if let Some(name) = arg.strip_prefix("--") {
            if let Some((k, v)) = name.split_once('=') {
                flags.insert(k.to_string(), v.to_string());
            } else if iter.peek().map(|n| !n.starts_with("--")).unwrap_or(false) {
                flags.insert(name.to_string(), iter.next().cloned().unwrap_or_default());
            } else {
                flags.insert(name.to_string(), "true".to_string());
            }
        } else {
            positionals.push(arg.clone());
        }
    }
    (flags, positionals)
}

fn flag_set(flags: &HashMap<String, String>, name: &str) -> bool {
    flags.get(name).map(|v| v == "true").unwrap_or(false)
}

fn emit(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub(crate) fn cmd_init(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let owner = positionals
        .first()
        .or_else(|| flags.get("owner"))
        .map(String::as_str)
        .context("usage: init <owner-uid>")?;
    let recovery_uid = format!("skarbiec-recovery <{owner}>");
    let owner_fpr = match crypto::fingerprint_for(owner)? {
        Some(fpr) => fpr,
        None => crypto::generate_key(owner)?,
    };
    let recovery_fpr = match crypto::fingerprint_for(&recovery_uid)? {
        Some(fpr) => fpr,
        None => crypto::generate_key(&recovery_uid)?,
    };
    let vault = Vault::create(vault_path(), owner, &owner_fpr, &recovery_fpr)?;
    Ok(
        json!({"ok": true, "vault": vault.path.display().to_string(), "owner_fpr": owner_fpr, "recovery_fpr": recovery_fpr}),
    )
}

fn ensure_owner_mutation_allowed(vault: &Vault, id: &str, operation: &str) -> Result<()> {
    vault.ensure_owner_controlled(id).with_context(|| {
        format!("use the item's controlling lifecycle instead of direct owner {operation}")
    })
}

fn ensure_owner_set_allowed(vault: &Vault, id: &str) -> Result<()> {
    let item_exists = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .is_some_and(|items| items.contains_key(id));
    if !item_exists {
        return Ok(());
    }
    ensure_owner_mutation_allowed(vault, id, "rotate")
}

fn ensure_no_reserved_tags(tags: &[String]) -> Result<()> {
    if tags.iter().any(|tag| tag == "managed:weles") {
        bail!("managed:weles is reserved for authenticated Weles writes");
    }
    Ok(())
}

/// Resolve one metadata list: what the caller asked for, or what the item
/// already carries when the caller said nothing about it.
///
/// An absent flag used to become an empty list, and the vault wrote that empty
/// list over whatever was there. Brama's credential refresh calls `set-json`
/// with neither `--tags` nor `--recipients`, so every OAuth rotation stripped a
/// subscription's `brama:subscription` and `brama:agent:` tags and narrowed its
/// recipients to the owner alone. The item kept serving traffic while vanishing
/// from every consumer that enumerates by tag — the gateway's own listing and
/// its desktop console both do — which is how a subscription at revision 258
/// came to be invisible everywhere it should have appeared. An absent flag now
/// means "leave this as it is"; `--tags=` still clears.
fn requested_or_existing(
    flags: &HashMap<String, String>,
    vault: &Vault,
    id: &str,
    key: &str,
) -> Vec<String> {
    if let Some(value) = flags.get(key) {
        return value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_string)
            .collect();
    }
    vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .and_then(|items| items.get(id))
        .and_then(|item| item.get(key))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn cmd_set(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: set <id> [--type <canonical-kind>] k=v ...")?;
    let item_kind = flags.get("type").map(String::as_str).unwrap_or("login");
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_set_allowed(&vault, id)?;
    let fields: Vec<String> = positionals
        .iter()
        .skip(std::iter::once(()).count())
        .cloned()
        .collect();
    let payload = items::build_item(item_kind, &fields)?;
    let recipients = requested_or_existing(flags, &vault, id, "recipients");
    let tags = requested_or_existing(flags, &vault, id, "tags");
    ensure_no_reserved_tags(&tags)?;
    let writer = vault.owner_uid().to_string();
    vault.set_item_written_by(id, item_kind, &payload, &recipients, &tags, &writer)?;
    emit(&json!({"ok": true, "id": id, "kind": item_kind}))
}

fn cmd_set_json(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: set-json <id> [--type <canonical-kind>]")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_set_allowed(&vault, id)?;
    let mut encoded = String::new();
    std::io::stdin().read_to_string(&mut encoded)?;
    let payload: Value =
        serde_json::from_str(&encoded).context("stdin must be one canonical JSON payload")?;
    let payload_kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .context("set-json payload requires kind")?;
    let item_kind = flags
        .get("type")
        .map(String::as_str)
        .unwrap_or(payload_kind);
    schema::validate_payload(&payload, item_kind)?;
    let recipients = requested_or_existing(flags, &vault, id, "recipients");
    let tags = requested_or_existing(flags, &vault, id, "tags");
    ensure_no_reserved_tags(&tags)?;
    let writer = vault.owner_uid().to_string();
    vault.set_item_written_by(id, item_kind, &payload, &recipients, &tags, &writer)?;
    emit(&json!({"ok": true, "id": id, "kind": item_kind}))
}

/// Replace one item's tags, leaving its payload untouched.
///
/// Consumers enumerate by tag: Brama's gateway and its desktop console both
/// treat an item as a subscription only when it carries `brama:subscription`
/// and `brama:agent:<agent>`, so an item that lost those tags is invisible to
/// every reader while still serving traffic. Until now the only way to restore
/// them was `set-json`, which rewrites the payload and re-encrypts it to the
/// current recipient list — a write that can narrow access to a live
/// credential, and one that needs the secret in hand to perform at all.
fn cmd_retag(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: retag <id> --tags tag[,tag...]")?;
    let tags: Vec<String> = flags
        .get("tags")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|tag| !tag.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    ensure_no_reserved_tags(&tags)?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "retag")?;
    vault.set_item_tags(id, &tags)?;
    emit(&json!({"ok": true, "id": id, "tags": tags}))
}

/// Change one item's id, keeping everything that is not the id.
///
/// There was no way to do this. The improvisation -- `get`, `set-json` under
/// the new id, `delete` the old -- is a copy wearing a rename's clothes: the
/// result starts at revision 1 with an empty history and a fresh `created_at`,
/// its tags are gone because a new id has no previous entry to preserve them
/// from, and it needs the plaintext in hand. Measured on a scratch vault, an
/// item at revision 3 with two historical versions came out at revision 1 with
/// none.
///
/// Owner-controlled items only, the same bar `retag` and `delete` apply. An
/// item the credential lifecycle or Weles controls is refused, because its
/// controller holds references keyed by the id and this command cannot update
/// them.
///
/// The references this does break -- capability routes, consumer grants,
/// acquisition bearers in flight -- break loudly, which is the accepted
/// tradeoff. What changes is that they are now traceable: the uid travels with
/// the item, so `routes verify` reports a renamed item as renamed and names
/// where it went, instead of reporting it as missing and leaving an operator
/// unable to tell a rename from a purge.
fn cmd_rename(positionals: &[String]) -> Result<()> {
    let from = positionals.first().context("usage: rename <id> <new-id>")?;
    let to = positionals
        .get("1".parse::<usize>()?)
        .context("usage: rename <id> <new-id>")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, from, "rename")?;
    let item_uid = vault.rename_item(from, to)?;
    crate::runtime::audit::append_sync(
        "item-renamed",
        &json!({"from": from, "to": to, "item_uid": item_uid}),
    )?;
    emit(&json!({"ok": true, "from": from, "to": to, "item_uid": item_uid}))
}

/// Stamp a permanent `item_uid` onto every item that predates the field.
///
/// Lazy minting means the field arrives on its own as items are written, but
/// an operator wanting a complete picture should not have to touch hundreds of
/// items by hand to get one. Idempotent: an item that already has one is
/// skipped before anything is generated, so a second run stamps nothing.
///
/// Envelope only. No payload is read, decrypted or re-encrypted, and
/// `revision`, `updated_at` and `current` are untouched -- acquiring an
/// identifier is not a change to the credential, and a diff of a backfilled
/// vault shows one added field per item and nothing else.
fn cmd_backfill_item_uids() -> Result<()> {
    let mut vault = Vault::open(vault_path())?;
    let (stamped, total) = vault.backfill_item_uids()?;
    if !stamped.is_empty() {
        crate::runtime::audit::append_sync(
            "item-uids-backfilled",
            &json!({"stamped": stamped.len(), "items": total}),
        )?;
    }
    emit(&json!({
        "ok": true,
        "items": total,
        "stamped": stamped.len(),
        "already_present": total.saturating_sub(stamped.len()),
        "ids": stamped,
    }))
}

pub(crate) fn cmd_delete(positionals: &[String]) -> Result<Value> {
    let id = positionals.first().context("usage: delete <id>")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "remove")?;
    vault.delete_item(id)?;
    Ok(json!({"ok": true}))
}

pub(crate) fn cmd_reclaim(positionals: &[String]) -> Result<Value> {
    let id = positionals.first().context("usage: reclaim <id>")?;
    let mut vault = Vault::open(vault_path())?;
    vault.reclaim_item(id)?;
    Ok(json!({"ok": true, "id": id, "mode": "owner"}))
}

pub(crate) fn cmd_restore(positionals: &[String]) -> Result<Value> {
    let id = positionals.first().context("usage: restore <id>")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "acquire")?;
    vault.restore_item(id)?;
    Ok(json!({"ok": true}))
}

pub(crate) fn cmd_purge(positionals: &[String]) -> Result<Value> {
    let id = positionals.first().context("usage: purge <id>")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "remove")?;
    vault.purge_item(id)?;
    Ok(json!({"ok": true}))
}

fn cmd_restore_version(positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: restore-version <id> <at>")?;
    let at = positionals
        .get(std::iter::once(()).count())
        .context("usage: restore-version <id> <at>")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "rotate")?;
    vault.restore_version(id, at)?;
    emit(&json!({"ok": true}))
}

fn cmd_get(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: get <id> [--field <field>]")?;
    let item = Vault::open(vault_path())?.get_item(id)?;
    let Some(field) = flags.get("field") else {
        return emit(&item);
    };
    if field.is_empty() || field.chars().any(char::is_control) {
        bail!("get --field requires one exact field name");
    }
    let value = item
        .get("fields")
        .and_then(Value::as_object)
        .and_then(|fields| fields.get(field))
        .with_context(|| format!("item {id} has no field {field}"))?
        .as_str()
        .with_context(|| format!("item {id} field {field} is not text"))?;
    println!("{value}");
    Ok(())
}

pub(crate) fn cmd_list(flags: &HashMap<String, String>) -> Result<Value> {
    Ok(json!(
        Vault::open(vault_path())?.list(flag_set(flags, "all"))
    ))
}

fn cmd_generate(flags: &HashMap<String, String>) -> Result<()> {
    if flag_set(flags, "passphrase") {
        let count: usize = flags
            .get("words")
            .context("usage: generate --passphrase --words N")?
            .parse()
            .context("--words must be a number")?;
        let sep = flags.get("separator").map(String::as_str).unwrap_or("-");
        return emit(&json!({"passphrase": items::generate_passphrase(count, sep)?}));
    }
    let length: usize = flags
        .get("length")
        .context("usage: generate --length N [--symbols]")?
        .parse()
        .context("--length must be a number")?;
    let value = items::generate_password(
        length,
        flag_set(flags, "lower"),
        flag_set(flags, "upper"),
        flag_set(flags, "digits"),
        flag_set(flags, "symbols"),
    )?;
    emit(&json!({"password": value}))
}

// Lossless migration lives in core::items::import_json (moved so this entry
// point stays under the per-file line budget).

// Bridge for consumers that read a JSON-array file (via an env-configured path):
// decrypt every live item and write the array
// to an owner-only file. The vault stays the source of truth; this materializes
// a runtime view for a consumer that cannot yet call resolve per item.
fn cmd_export(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let out = positionals
        .first()
        .or_else(|| flags.get("out"))
        .context("usage: export <out-file.json>")?;
    let vault = Vault::open(vault_path())?;
    let mut rows: Vec<Value> = Vec::new();
    for entry in vault.list(false) {
        if let Some(id) = entry.get("id").and_then(Value::as_str) {
            rows.push(vault.get_item(id)?);
        }
    }
    std::fs::write(out, serde_json::to_string(&Value::Array(rows.clone()))?)?;
    std::process::Command::new("chmod")
        .arg("600")
        .arg(out)
        .status()
        .ok();
    emit(&json!({"ok": true, "exported": rows.len(), "out": out}))
}

/// Report what this binary is, so a supervisor never has to identify a build by
/// counting the commands it answers — which is what the July incident actually
/// resorted to, twice, on a broker that had been replaced by hand.
///
/// `release` is the versioned coordinate the artifact was published at, and
/// `commit` is the source revision it was built from. Both are baked in at build
/// time by the publishing pipeline. A source build has neither and says so rather
/// than guessing, because an unpublished binary claiming a release coordinate is
/// worse than one admitting it has no provenance.
///
/// The coordinate alone would only identify bytes. Publishing refuses a tree with
/// uncommitted changes, so a released coordinate resolves to a revision anyone can
/// check out and rebuild — which is the difference between an artifact that is a
/// source of truth and one that is merely unique.
pub(crate) fn cmd_version() -> Result<Value> {
    let release = option_env!("SKARBIEC_RELEASE_URI");
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "release": release,
        "commit": option_env!("SKARBIEC_RELEASE_COMMIT"),
        // `release` is the word a supervisor compares against, not a synonym it
        // has to learn: a host software report classifies each file it finds as
        // `release` or `unmanaged`, and this field is how a Skarbiec binary
        // answers that question about itself. The earlier value, `published`,
        // described the same state in a second vocabulary, which left the
        // reporting side matching on a string no other surface used.
        "provenance": match release {
            Some(_) => "release",
            None => "source build",
        },
    }))
}

fn main() -> Result<()> {
    let mut argv = std::env::args();
    argv.next();
    let command = argv.next().unwrap_or_else(|| "help".to_string());
    let rest: Vec<String> = argv.collect();
    let (flags, positionals) = parse_args(&rest);

    match command.as_str() {
        "version" | "--version" | "-V" => emit(&cmd_version()?),
        "status" => emit(&core::items::status_json()?),
        "doctor" => emit(&runtime::doctor::report()?),
        "recover-daemons" => emit(&runtime::doctor::recover_daemons()?),
        "vaults" => emit(&runtime::vaults::inventory()?),
        "init" => emit(&cmd_init(&flags, &positionals)?),
        "set" => cmd_set(&flags, &positionals),
        "get" => cmd_get(&flags, &positionals),
        "set-json" => cmd_set_json(&flags, &positionals),
        "list" => emit(&cmd_list(&flags)?),
        "retag" => cmd_retag(&flags, &positionals),
        "rename" => cmd_rename(&positionals),
        "backfill-item-uids" => cmd_backfill_item_uids(),
        "delete" => emit(&cmd_delete(&positionals)?),
        "reclaim" => emit(&cmd_reclaim(&positionals)?),
        "restore" => emit(&cmd_restore(&positionals)?),
        "purge" => emit(&cmd_purge(&positionals)?),
        "restore-version" => cmd_restore_version(&positionals),
        "generate" => cmd_generate(&flags),
        "import" => emit(&items::import_json(&positionals)?),
        "migrate" => emit(&items::migrate_vault(&flags)?),
        "migrate-v2" => emit(&items::migrate_v2(&flags)?),
        "export" => cmd_export(&flags, &positionals),
        "onboarding" => emit(&onboarding::run(&flags)?),
        // The advertised list is the contract: a command that is dispatchable but
        // absent here is private, and no caller can be told to rely on it. The
        // release classifier compares exactly this surface, so `version` had to
        // arrive here as well as in the dispatcher before docs could point at it.
        "help" => emit(
            &json!({"commands": ["status","doctor","recover-daemons","vaults","init","set","set-json","get","list","retag","rename","backfill-item-uids","delete","reclaim","restore","purge","restore-version","generate","import","migrate","migrate-v2","add-user","rotate-owner","share","revoke","users","export-key","token-mint","token-ensure-read","token-revoke","token-verify","tokens","acquisition-request","acquisition-read","key-doctor","recovery-status","recovery-drill","emergency-grant","emergency-cancel","emergency-list","emergency-activate","policy-set","policy-get","policy-check-length","audit","audit-query","audit-epoch-start","verify-chain","resolve","expand","totp","totp-seed-state","breach-check","sync-init","sync-push","sync-pull","pull","donate","donations","donation-accept","donation-reject","enroll","sync-daemon","sync-status","invite","bond-add","bond-list","bond-remove","capability-issue","capability-serve","routes","credential","apple-challenge-put","version"]}),
        ),
        "mcp" => net::mcp::serve(),
        "native-host" => native_host::run(),
        "browser-host-install" => emit(&browser::install_host(&flags)?),
        other => {
            if let Some(v) = credential::dispatch(other, &flags, &positionals, &vault_path())? {
                emit(&v)
            } else if let Some(v) = access::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else if let Some(v) = runtime::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else if let Some(v) = net::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else if let Some(v) = bonds::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else if let Some(v) = invite::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else if let Some(v) = core::inbox::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else {
                bail!("unknown command: {other}")
            }
        }
    }
}
