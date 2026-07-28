// skarbiec-entitlements-router — self-contained secrets vault (Rust).
// Per-recipient gpg encryption, versioned items, trash/restore, generator.
// Access/runtime/net layers are wired in sibling modules. No numeric literals:
// counts/lengths arrive from argv via parse(), never as source constants.

mod access;
mod core;
mod credential;
mod net;
mod release;
mod runtime;
mod secure_input;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{IsTerminal, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use core::{chrome_cards, crypto, items, vault::Vault};
use zeroize::{Zeroize, Zeroizing};

fn vault_path() -> PathBuf {
    if let Ok(p) = std::env::var("SKARBIEC_VAULT_FILE") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("skarbiec.vault.json")
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

fn ensure_not_apple_challenge_id(id: &str) -> Result<()> {
    if id.starts_with("challenge:apple/") {
        bail!("Apple challenges may only be stored with apple-challenge-put over stdin");
    }
    Ok(())
}

fn cmd_set(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: set <id> [--type t] [key=value ... | --value-file <absolute-path>]")?;
    ensure_not_apple_challenge_id(id)?;
    let item_type = flags.get("type").map(String::as_str).unwrap_or("login");
    if matches!(item_type, items::PAYMENT_CARD_TYPE | "card") {
        bail!("payment cards must be stored with card-set over stdin");
    }
    let fields: Vec<String> = positionals
        .iter()
        .skip(std::iter::once(()).count())
        .cloned()
        .collect();
    let secret = if let Some(value_file) = flags.get("value-file") {
        if !fields.is_empty() {
            bail!("--value-file conflicts with positional key=value fields");
        }
        let value = secure_input::read_value_file(std::path::Path::new(value_file))?;
        json!({"type": item_type, "value": value})
    } else {
        items::build_item(item_type, &fields)?
    };
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
    emit(&json!({"ok": true, "id": id}))
}
fn cmd_card_set(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: card-set <id> [--recipients a,b] [--tags x,y]")?;
    ensure_not_apple_challenge_id(id)?;
    if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
        bail!("payment card id must contain 1..256 non-control characters");
    }
    if std::io::stdin().is_terminal() {
        bail!("card-set requires a JSON object piped on stdin");
    }

    let mut payload = Zeroizing::new(Vec::new());
    std::io::stdin().take(65_537).read_to_end(&mut payload)?;
    if payload.is_empty() || payload.len() > 65_536 {
        bail!("payment card stdin must contain 1..65536 bytes");
    }
    let (secret, last4) = items::payment_card_from_json(&payload)?;
    let recipients: Vec<String> = flags
        .get("recipients")
        .map(|value| value.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    let tags: Vec<String> = flags
        .get("tags")
        .map(|value| value.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    Vault::open(vault_path())?.set_item(
        id,
        items::PAYMENT_CARD_TYPE,
        secret.as_value(),
        &recipients,
        &tags,
    )?;
    emit(&json!({
        "ok": true,
        "id": id,
        "type": items::PAYMENT_CARD_TYPE,
        "last4": last4
    }))
}
fn cmd_card_import_chrome(flags: &HashMap<String, String>) -> Result<()> {
    let chrome_root = flags
        .get("chrome-root")
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(chrome_cards::default_chrome_root)?;
    let mut vault = Vault::open(vault_path())?;
    let report = chrome_cards::import_into_vault(
        &mut vault,
        &chrome_root,
        flags.get("profiles").map(String::as_str),
        flag_set(flags, "replace"),
    )?;
    emit(&report)
}
fn cmd_apple_credential_put(positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: apple-credential-put <origin:https://idmsa.apple.com/email|origin:https://idmsa.apple.com/password>")?;
    if !matches!(
        id.as_str(),
        "origin:https://idmsa.apple.com/email" | "origin:https://idmsa.apple.com/password"
    ) {
        bail!("unsupported Apple credential resource");
    }
    let mut bytes = Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > 4096 {
        bytes.zeroize();
        bail!("Apple credential must contain 1..4096 UTF-8 bytes");
    }
    let secret = match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(error) => {
            let mut invalid = error.into_bytes();
            invalid.zeroize();
            bail!("Apple credential must be UTF-8");
        }
    };
    let mut value = json!({"type": "credential", "value": secret});
    let result = match Vault::open(vault_path()) {
        Ok(mut vault) => vault.set_item(id, "credential", &value, &[], &[]),
        Err(error) => Err(error),
    };
    if let Some(Value::String(text)) = value.get_mut("value") {
        text.zeroize();
    }
    result?;
    emit(&json!({"ok": true, "id": id}))
}
// Recipient uids for credential-put: --recipient uid1,uid2 (the flag parser is
// last-write-wins, so repeated flags do not accumulate; commas carry the list).
// Both singular and plural spellings are accepted. No flag = vault defaults.
fn recipient_flags(flags: &HashMap<String, String>) -> Vec<String> {
    let mut recipients = Vec::new();
    for key in ["recipient", "recipients"] {
        if let Some(value) = flags.get(key) {
            recipients.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|uid| !uid.is_empty())
                    .map(str::to_string),
            );
        }
    }
    recipients.dedup();
    recipients
}

fn cmd_credential_put(positionals: &[String], flags: &HashMap<String, String>) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: credential-put <item-id> [--recipient uid[,uid...]]")?;
    ensure_not_apple_challenge_id(id)?;
    if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
        bail!("credential item id must contain 1..256 non-control characters");
    }

    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin().take(8193).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > 8192 {
        bail!("credential stdin must contain 1..8192 UTF-8 bytes");
    }
    let secret = std::str::from_utf8(&bytes).context("credential stdin must be UTF-8")?;
    let requested_recipients = recipient_flags(flags);
    let mut value = json!({"type": "credential", "value": secret});
    let result = match Vault::open(vault_path()) {
        Ok(mut vault) => {
            let existing = vault
                .doc()
                .get("items")
                .and_then(|items| items.get(id))
                .cloned();
            let item_type = existing
                .as_ref()
                .and_then(|item| item.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("credential")
                .to_owned();
            let tags = existing
                .as_ref()
                .and_then(|item| item.get("tags"))
                .and_then(Value::as_array)
                .map(|tags| {
                    tags.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(|| {
                    vec!["credential-request".to_owned(), "weles".to_owned()]
                });
            let mut recipients = vault.item_recipient_uids(id);
            for uid in requested_recipients {
                if !recipients.contains(&uid) {
                    recipients.push(uid);
                }
            }
            let unknown = recipients
                .iter()
                .find(|uid| vault.recipient_fpr(uid).is_none());
            match unknown {
                Some(uid) => Err(anyhow::anyhow!("unknown recipient: {uid}")),
                None => vault.set_item(id, &item_type, &value, &recipients, &tags),
            }
        }
        Err(error) => Err(error),
    };
    if let Some(Value::String(text)) = value.get_mut("value") {
        text.zeroize();
    }
    result?;
    access::reauth::push_vault_to_stado().map_err(anyhow::Error::msg)?;
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

// Lossless migration: store each row of a JSON array verbatim (nested metadata,
// TOTP seeds, tags preserved) under its own id. Recipients default to owner +
// recovery unless the row already carries a `recipients` array.
fn cmd_import(positionals: &[String]) -> Result<()> {
    let path = positionals.first().context("usage: import <file.json>")?;
    let rows: Value = serde_json::from_str(
        &std::fs::read_to_string(path).with_context(|| format!("read {path}"))?,
    )?;
    let rows = rows
        .as_array()
        .context("import file must be a JSON array of rows")?;
    let mut vault = Vault::open(vault_path())?;
    let mut imported = Vec::new();
    let mut skipped = Vec::new();
    for row in rows {
        match row.get("id").and_then(Value::as_str) {
            Some(id) => {
                ensure_not_apple_challenge_id(id)?;
                let item_type = row
                    .get("type")
                    .or_else(|| row.get("category"))
                    .and_then(Value::as_str)
                    .unwrap_or("login")
                    .to_string();
                let recipients: Vec<String> = row
                    .get("recipients")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let tags: Vec<String> = row
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                vault.set_item(id, &item_type, row, &recipients, &tags)?;
                imported.push(id.to_string());
            }
            None => skipped.push(
                row.get("display_name")
                    .and_then(Value::as_str)
                    .unwrap_or("(no id)")
                    .to_string(),
            ),
        }
    }
    emit(&json!({"ok": true, "imported": imported.len(), "skipped": skipped.len()}))
}

// Bridge for consumers that read a JSON-array file (e.g. the Weles worker via
// WELES_SERVICE_CREDENTIALS_FILE): decrypt every live item and write the array
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
    let path = PathBuf::from(out);
    if !path.is_absolute() {
        bail!("export output path must be absolute");
    }
    let parent = path.parent().context("export output has no parent")?;
    let parent_meta = std::fs::symlink_metadata(parent)?;
    if parent_meta.file_type().is_symlink()
        || !parent_meta.is_dir()
        || parent_meta.uid() != unsafe { libc::geteuid() }
        || parent_meta.permissions().mode() & 0o077 != 0
    {
        bail!("export output directory must be owner-only");
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    file.write_all(serde_json::to_string(&Value::Array(rows.clone()))?.as_bytes())?;
    file.sync_all()?;
    emit(&json!({"ok": true, "exported": rows.len()}))
}

const RESEND_ENV_IDS: &[&str] = &["RESEND_API_KEY", "RESEND_RECEIVING_API_KEY"];

fn parse_resend_token(raw: &str) -> Result<String> {
    let value = raw.trim();
    let value = value
        .strip_prefix('\'')
        .and_then(|inner| inner.strip_suffix('\''))
        .or_else(|| {
            value
                .strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
        })
        .unwrap_or(value)
        .trim();
    if value.is_empty() || value == "UNSET" {
        bail!("Resend source contains an unset value");
    }
    let suffix = value
        .strip_prefix("re_")
        .filter(|suffix| !suffix.is_empty())
        .context("Resend source contains an invalid value")?;
    if !suffix
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        bail!("Resend source contains an invalid value");
    }
    Ok(value.to_string())
}

fn parse_resend_source(path: &PathBuf) -> Result<HashMap<String, String>> {
    if !path.is_absolute() {
        bail!("seed-resend source must be absolute");
    }
    let body = std::fs::read_to_string(path).context("read Resend source file")?;
    let mut values = HashMap::new();
    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let assignment = line.strip_prefix("export ").unwrap_or(line);
        let (key, raw_value) = assignment
            .split_once('=')
            .context("Resend source contains a non-dotenv line")?;
        if !RESEND_ENV_IDS.contains(&key) {
            continue;
        }
        if values
            .insert(key.to_string(), parse_resend_token(raw_value)?)
            .is_some()
        {
            bail!("Resend source contains a duplicate supported key");
        }
    }
    if !values.contains_key("RESEND_RECEIVING_API_KEY") {
        bail!("Resend source is missing RESEND_RECEIVING_API_KEY");
    }
    Ok(values)
}

fn env_item_meta(vault: &Vault, id: &str) -> Result<(String, Vec<String>)> {
    let stored = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(id))
        .context("Resend vault item is missing")?;
    if stored.get("type").and_then(Value::as_str) != Some("env") {
        bail!("Resend vault item is not an env item");
    }
    let tags = stored
        .get("tags")
        .and_then(Value::as_array)
        .map(|tags| {
            tags.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(("env".to_string(), tags))
}

fn cmd_seed_resend(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    if !flags.is_empty() || positionals.len() != std::iter::once(()).count() {
        bail!("usage: seed-resend <absolute-source-file>");
    }
    let source = PathBuf::from(&positionals[usize::default()]);
    let source_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .context("Resend source has no valid basename")?
        .to_string();
    let values = parse_resend_source(&source)?;
    let mut vault = Vault::open(vault_path())?;
    let mut pending = Vec::new();
    for id in RESEND_ENV_IDS {
        let Some(value) = values.get(*id) else {
            continue;
        };
        let (item_type, tags) = env_item_meta(&vault, id)?;
        let recipients = vault.item_recipient_uids(id);
        let mut secret = Vault::get_item(&vault, id)?;
        secret
            .as_object_mut()
            .context("Resend vault item is not an object")?
            .insert("value".to_string(), Value::String(value.clone()));
        pending.push((id.to_string(), item_type, tags, recipients, secret));
    }
    let mut imported = Vec::new();
    for (id, item_type, tags, recipients, secret) in pending {
        vault.set_item(&id, &item_type, &secret, &recipients, &tags)?;
        imported.push(id);
    }
    runtime::audit::append(
        "seed-resend",
        &json!({"ids": imported, "source": source_name}),
    )?;
    emit(&json!({"ok": true, "imported": imported}))
}

fn main() -> Result<()> {
    let mut argv = std::env::args();
    argv.next();
    let command = argv.next().unwrap_or_else(|| "help".to_string());
    let rest: Vec<String> = argv.collect();
    let (flags, positionals) = parse_args(&rest);

    match command.as_str() {
        "init" => cmd_init(&flags, &positionals),
        "set" => cmd_set(&flags, &positionals),
        "card-set" => cmd_card_set(&flags, &positionals),
        "card-import-chrome" => cmd_card_import_chrome(&flags),
        "apple-credential-put" => cmd_apple_credential_put(&positionals),
        "credential-put" => cmd_credential_put(&positionals, &flags),
        "get" => cmd_get(&positionals),
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
        "import" => cmd_import(&positionals),
        "export" => cmd_export(&flags, &positionals),
        "seed-resend" => cmd_seed_resend(&flags, &positionals),
        "release-publish" => emit(&release::command(&flags, &positionals)?),
        "help" => emit(
            &json!({"commands": ["init","set","card-set","card-import-chrome","apple-credential-put","credential-put","get","list","delete","restore","purge","restore-version","generate","add-user","share","revoke","users","export-key","token-mint","token-revoke","token-verify","tokens","recovery-status","emergency-grant","emergency-cancel","emergency-list","emergency-activate","policy-set","policy-get","policy-check-length","audit","verify-chain","resolve","expand","totp","breach-check","mailbox-broker","mailbox-probe","seed-resend","sync-init","sync-push","sync-pull","serve","mcp","apple-challenge-put","capability-serve","capability-issue","capability-status","capability-cancel","capability-delegate","release-publish","credential-request","credential-return", "rotate-owner"]}),
        ),
        "mcp" => net::mcp::serve(),
        other => {
            if let Some(v) = credential::dispatch(&vault_path(), other, &flags, &positionals)? {
                return emit(&v);
            }
            if let Some(v) = access::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else if let Some(v) = runtime::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else if let Some(v) = net::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else {
                bail!("unknown command: {other}")
            }
        }
    }
}
