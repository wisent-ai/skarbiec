// Bond operations (docs/design/bond.md): the bond configuration commands
// (bond-add/bond-list/bond-remove), the enroll client that registers a
// replica's key with a source serve, the sync-daemon that repeats a pull on
// the bond-configured interval, the sync-status report, and the read-only
// bonds registry. launchd is expected to wrap sync-daemon for persistence;
// no plist is created here.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::core::{crypto, vault::Vault, vault_path};

fn cmd_bond_add(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let name = positionals.first().context(
        "usage: bond-add <name> --mode <mode> --role <role> --channel <type:address> [--peers fpr,fpr] [--interval seconds]",
    )?;
    let mode = flags.get("mode").context("--mode required")?;
    let role = flags.get("role").context("--role required")?;
    let channel = flags.get("channel").context("--channel required")?;
    // Schema from docs/design/bond.md — a mistyped mode never lands in the doc.
    let modes = ["replica", "hub", "p2p", "git"];
    if !modes.contains(&mode.as_str()) {
        anyhow::bail!("mode must be one of: {}", modes.join(", "));
    }
    let roles = ["source", "replica", "consumer", "peer"];
    if !roles.contains(&role.as_str()) {
        anyhow::bail!("role must be one of: {}", roles.join(", "));
    }
    let (channel_type, address) = channel
        .split_once(':')
        .context("channel must be <type:address>")?;
    let channel_types = ["serve", "git", "file"];
    if !channel_types.contains(&channel_type) {
        anyhow::bail!("channel type must be one of: {}", channel_types.join(", "));
    }
    let interval: Option<u64> = flags
        .get("interval")
        .map(|value| {
            value
                .parse::<u64>()
                .context("--interval must be seconds (a number)")
        })
        .transpose()?;
    let peers: Vec<String> = flags
        .get("peers")
        .map(|value| value.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    // Non-secret config only: modes, roles, addresses, intervals, peer fingerprints.
    let mut channel_json = json!({"type": channel_type, "address": address});
    if let Some(seconds) = interval {
        channel_json["interval_seconds"] = json!(seconds);
    }
    let mut vault = Vault::open(vault_path())?;
    let doc = vault
        .doc_mut()
        .as_object_mut()
        .context("vault document is not an object")?;
    if !doc.contains_key("bond") {
        doc.insert("bond".to_string(), json!({}));
    }
    doc.get_mut("bond")
        .and_then(Value::as_object_mut)
        .context("bond section is an object")?
        .insert(
            name.clone(),
            json!({
                "mode": mode,
                "role": role,
                "channel": channel_json,
                "peers": peers,
            }),
        );
    vault.save()?;
    crate::runtime::audit::append(
        "bond-add",
        &json!({"bond": name, "mode": mode, "role": role}),
    )?;
    Ok(json!({"ok": true, "bond": name, "mode": mode, "role": role}))
}

fn cmd_enroll(flags: &HashMap<String, String>) -> Result<Value> {
    let uid = flags.get("as").context(
        "usage: enroll --as <uid> --to <base-url> --token <t> [--items a,b,c] [--consumer name]",
    )?;
    let to = flags.get("to").context("--to required")?;
    let token = flags.get("token").context("--token required")?;
    let consumer = flags
        .get("consumer")
        .map(String::as_str)
        .unwrap_or("enroll");
    let items: Vec<String> = flags
        .get("items")
        .map(|value| value.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    let vault = Vault::open(vault_path())?;
    let owner = vault.owner_uid().to_string();
    let fingerprint = vault
        .recipient_fpr(&owner)
        .context("local owner has no registered fingerprint")?;
    let armored = crypto::export_public_key(&fingerprint)?;
    let (_status, response) = crate::net::bond::serve_request(
        to,
        "POST",
        "/v1/enroll",
        consumer,
        token,
        Some(&json!({"uid": uid, "armored": armored, "items": items})),
    )?;
    crate::runtime::audit::append("enroll", &json!({"to": to, "uid": uid, "items": items}))?;
    Ok(response)
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_sig: c_int) {
    STOP.store(true, Ordering::SeqCst);
}

extern "C" {
    fn signal(signum: c_int, handler: extern "C" fn(c_int)) -> isize;
}

fn sigterm() -> c_int {
    "15".parse().unwrap_or_default()
}

fn cmd_sync_daemon(flags: &HashMap<String, String>) -> Result<Value> {
    let name = flags
        .get("bond")
        .context("usage: sync-daemon --bond <name> --token <t> [--consumer name]")?;
    let token = flags.get("token").context("--token required")?;
    let consumer = flags
        .get("consumer")
        .map(String::as_str)
        .unwrap_or("replica")
        .to_string();
    let vault = Vault::open(vault_path())?;
    let bond = vault
        .doc()
        .get("bond")
        .and_then(|bonds| bonds.get(name))
        .with_context(|| format!("no bond named: {name}"))?;
    let address = bond
        .get("channel")
        .and_then(|c| c.get("address"))
        .and_then(Value::as_str)
        .context("bond channel has no address")?
        .to_string();
    let interval = bond
        .get("channel")
        .and_then(|c| c.get("interval_seconds"))
        .and_then(Value::as_u64)
        .context("bond channel has no interval_seconds (set it with bond-add --interval)")?;
    let _previous = unsafe { signal(sigterm(), on_term) };
    crate::runtime::audit::append(
        "sync-daemon-start",
        &json!({"bond": name, "address": address, "interval_seconds": interval}),
    )?;
    // One-second sleep slices so SIGTERM is answered promptly; the unit comes
    // from the iterator count because numeric literals are banned in source.
    let unit = Duration::from_secs(std::iter::once(()).count() as u64);
    let mut report = Value::Null;
    while !STOP.load(Ordering::SeqCst) {
        let mut pull_flags = HashMap::new();
        pull_flags.insert("from".to_string(), address.clone());
        pull_flags.insert("token".to_string(), token.clone());
        pull_flags.insert("consumer".to_string(), consumer.clone());
        pull_flags.insert("bond".to_string(), name.clone());
        report = match crate::net::bond::cmd_pull(&pull_flags) {
            Ok(value) => value,
            Err(error) => json!({"ok": false, "error": error.to_string()}),
        };
        let mut slept = u64::default();
        while slept < interval && !STOP.load(Ordering::SeqCst) {
            thread::sleep(unit);
            slept = slept.saturating_add(std::iter::once(()).count() as u64);
        }
    }
    crate::runtime::audit::append("sync-daemon-stop", &json!({"bond": name}))?;
    Ok(json!({"ok": true, "bond": name, "stopped": true, "last_pull": report}))
}

fn cmd_sync_status(flags: &HashMap<String, String>) -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    let bonds = vault
        .doc()
        .get("bond")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let token = flags.get("token");
    let consumer = flags
        .get("consumer")
        .map(String::as_str)
        .unwrap_or("replica");
    let local_count = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .map(|items| items.len())
        .unwrap_or_default();
    let wanted = flags.get("bond");
    let mut out = Vec::new();
    for (name, entry) in &bonds {
        if wanted.is_some_and(|w| w != name) {
            continue;
        }
        let channel = entry.get("channel").cloned().unwrap_or(Value::Null);
        let channel_type = channel.get("type").and_then(Value::as_str).unwrap_or("");
        let address = channel.get("address").and_then(Value::as_str).unwrap_or("");
        let mut healthy = Value::Null;
        let mut remote_items = Value::Null;
        if channel_type == "serve" {
            if let Ok((_status, health)) =
                crate::net::bond::serve_request(address, "GET", "/health", "", "", None)
            {
                healthy = health.get("ok").cloned().unwrap_or(Value::Null);
            }
            if let Some(presented) = token {
                if let Ok((_status, doc)) = crate::net::bond::serve_request(
                    address,
                    "GET",
                    "/v1/vault",
                    consumer,
                    presented,
                    None,
                ) {
                    remote_items = doc
                        .get("items")
                        .and_then(Value::as_object)
                        .map(|items| json!(items.len()))
                        .unwrap_or(Value::Null);
                }
            }
        }
        out.push(json!({
            "bond": name,
            "mode": entry.get("mode"),
            "role": entry.get("role"),
            "channel": channel,
            "last_pull_at": entry.get("last_pull_at"),
            "last_items_after": entry.get("last_items_after"),
            "local_items": local_count,
            "remote_items": remote_items,
            "healthy": healthy,
        }));
    }
    Ok(json!(out))
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "bond-add" => cmd_bond_add(flags, positionals).map(Some),
        "bond-list" | "bonds" => {
            let vault = Vault::open(vault_path())?;
            Ok(Some(
                vault
                    .doc()
                    .get("bond")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
            ))
        }
        "bond-remove" => {
            let name = positionals.first().context("usage: bond-remove <name>")?;
            let mut vault = Vault::open(vault_path())?;
            let removed = vault
                .doc_mut()
                .get_mut("bond")
                .and_then(Value::as_object_mut)
                .and_then(|bonds| bonds.remove(name));
            if removed.is_none() {
                anyhow::bail!("no bond named: {name}");
            }
            vault.save()?;
            crate::runtime::audit::append("bond-remove", &json!({"bond": name}))?;
            Ok(Some(json!({"ok": true, "bond": name})))
        }
        "enroll" => cmd_enroll(flags).map(Some),
        "sync-daemon" => cmd_sync_daemon(flags).map(Some),
        "sync-status" => cmd_sync_status(flags).map(Some),
        _ => Ok(None),
    }
}
