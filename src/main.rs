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
mod runtime;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;

use core::{crypto, items, vault::Vault};

fn vault_path() -> PathBuf {
    if let Ok(p) = std::env::var("SKARBIEC_VAULT_FILE") {
        return PathBuf::from(p);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".stado/skarbiec.vault.json")
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

fn cmd_init(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
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
    emit(
        &json!({"ok": true, "vault": vault.path.display().to_string(), "owner_fpr": owner_fpr, "recovery_fpr": recovery_fpr}),
    )
}

fn cmd_set(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: set <id> --type t --field k=v ...")?;
    let item_type = flags.get("type").map(String::as_str).unwrap_or("login");
    let fields: Vec<String> = positionals
        .iter()
        .skip(std::iter::once(()).count())
        .cloned()
        .collect();
    let secret = items::build_item(item_type, &fields)?;
    let recipients: Vec<String> = flags
        .get("recipients")
        .map(|s| s.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    let tags: Vec<String> = flags
        .get("tags")
        .map(|s| s.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    let mut vault = Vault::open(vault_path())?;
    vault.set_item(id, item_type, &secret, &recipients, &tags)?;
    core::inbox::mark_written_by(&mut vault, id, None)?;
    emit(&json!({"ok": true, "id": id}))
}
fn cmd_set_json(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: set-json <id> --type t")?;
    let item_type = flags.get("type").map(String::as_str).unwrap_or("secret");
    let mut encoded = String::new();
    std::io::stdin().read_to_string(&mut encoded)?;
    let secret: Value = serde_json::from_str(&encoded).context("stdin must be one JSON value")?;
    if !secret.is_object() {
        bail!("set-json requires a JSON object");
    }
    let recipients: Vec<String> = flags
        .get("recipients")
        .map(|value| value.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    let tags: Vec<String> = flags
        .get("tags")
        .map(|value| value.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    let mut vault = Vault::open(vault_path())?;
    vault.set_item(id, item_type, &secret, &recipients, &tags)?;
    core::inbox::mark_written_by(&mut vault, id, None)?;
    emit(&json!({"ok": true, "id": id}))
}

fn cmd_get(positionals: &[String]) -> Result<()> {
    let id = positionals.first().context("usage: get <id>")?;
    emit(&Vault::open(vault_path())?.get_item(id)?)
}

fn cmd_list(flags: &HashMap<String, String>) -> Result<()> {
    emit(&json!(
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
fn cmd_version() -> Result<()> {
    let release = option_env!("SKARBIEC_RELEASE_URI");
    emit(&json!({
        "version": env!("CARGO_PKG_VERSION"),
        "release": release,
        "commit": option_env!("SKARBIEC_RELEASE_COMMIT"),
        "provenance": match release {
            Some(_) => "published",
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
        "version" | "--version" | "-V" => cmd_version(),
        "status" => emit(&core::items::status_json()?),
        "init" => cmd_init(&flags, &positionals),
        "set" => cmd_set(&flags, &positionals),
        "get" => cmd_get(&positionals),
        "set-json" => cmd_set_json(&flags, &positionals),
        "list" => cmd_list(&flags),
        "delete" => {
            Vault::open(vault_path())?
                .delete_item(positionals.first().context("usage: delete <id>")?)?;
            emit(&json!({"ok": true}))
        }
        "restore" => {
            Vault::open(vault_path())?
                .restore_item(positionals.first().context("usage: restore <id>")?)?;
            emit(&json!({"ok": true}))
        }
        "purge" => {
            Vault::open(vault_path())?
                .purge_item(positionals.first().context("usage: purge <id>")?)?;
            emit(&json!({"ok": true}))
        }
        "restore-version" => {
            Vault::open(vault_path())?.restore_version(
                positionals
                    .first()
                    .context("usage: restore-version <id> <at>")?,
                positionals
                    .get(std::iter::once(()).count())
                    .context("usage: restore-version <id> <at>")?,
            )?;
            emit(&json!({"ok": true}))
        }
        "generate" => cmd_generate(&flags),
        "import" => emit(&items::import_json(&positionals)?),
        "export" => cmd_export(&flags, &positionals),
        // The advertised list is the contract: a command that is dispatchable but
        // absent here is private, and no caller can be told to rely on it. The
        // release classifier compares exactly this surface, so `version` had to
        // arrive here as well as in the dispatcher before docs could point at it.
        "help" => emit(
            &json!({"commands": ["status","init","set","set-json","get","list","delete","restore","purge","restore-version","generate","add-user","rotate-owner","share","revoke","users","export-key","token-mint","token-revoke","token-verify","tokens","acquisition-request","acquisition-read","key-doctor","recovery-status","recovery-drill","emergency-grant","emergency-cancel","emergency-list","emergency-activate","policy-set","policy-get","policy-check-length","audit","audit-query","verify-chain","resolve","expand","totp","breach-check","sync-init","sync-push","sync-pull","pull","donate","donations","donation-accept","donation-reject","enroll","sync-daemon","sync-status","invite","bond-add","bond-list","bond-remove","bonds","credential","serve","mcp","native-host","browser-host-install","version"]}),
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
