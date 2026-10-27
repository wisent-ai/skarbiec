// The bond configuration commands: what a bond is, in the vault.
//
// Only non-secret configuration lands here — modes, roles, addresses,
// intervals, peer fingerprints and, for a bond this vault pulls, the path of
// the owner-only file that holds its bearer. A mistyped mode, role or channel
// type is refused against the schema in docs/design/bond.md rather than
// written and discovered later by a pull that cannot run.

use super::*;
use crate::cli::args::OrUsage;

/// A new bond. A name already configured is refused with its mode and role;
/// `bond edit` changes it.
pub(crate) fn cmd_bond_add(
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    let name = positionals.first().or_usage(
        "usage: bond add <name> --mode <mode> --role <role> --channel <type:address> [--peers fpr,fpr] [--interval seconds] [--token-file path [--consumer name]]",
    )?;
    let vault = Vault::open(vault_path())?;
    if let Some(existing) = vault.doc().get("bond").and_then(|bonds| bonds.get(name)) {
        let stored = |field: &str| match existing[field].as_str() {
            Some(value) => value.to_string(),
            None => format!("no {field} recorded"),
        };
        anyhow::bail!(
            "bond {name} is already configured (mode {}, role {}); `skarbiec bond edit {name}` changes it",
            stored("mode"),
            stored("role"),
        );
    }
    drop(vault);
    write_bond(name, flags, "bond-add")
}

/// Change one configured bond: every flag `bond add` takes may be given,
/// and what is not given keeps its configured value. The result passes the
/// same checks a new bond does.
pub(crate) fn cmd_bond_edit(
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    let name = positionals.first().or_usage(
        "usage: bond edit <name> [--mode <mode>] [--role <role>] [--channel <type:address>] [--peers fpr,fpr] [--interval seconds] [--token-file path [--consumer name]]",
    )?;
    if flags.is_empty() {
        anyhow::bail!("bond edit changes nothing without a flag `bond add` takes");
    }
    let vault = Vault::open(vault_path())?;
    let current = vault
        .doc()
        .get("bond")
        .and_then(|bonds| bonds.get(name))
        .cloned()
        .with_context(|| format!("no bond named: {name}; `skarbiec bond list` lists them"))?;
    drop(vault);
    let mut merged = configured_flags(name, &current)?;
    merged.extend(
        flags
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    write_bond(name, &merged, "bond-edit")
}

/// The flags `bond add` would take to configure `bond` as it stands. A field
/// the bond holds in another shape is refused naming it: dropped, `bond
/// edit` wrote the bond back without it (its peers among them).
fn configured_flags(name: &str, bond: &Value) -> Result<HashMap<String, String>> {
    let mut flags = HashMap::new();
    let text = |field: &str, value: &Value| -> Result<Option<String>> {
        match value {
            Value::Null => Ok(None),
            Value::String(text) => Ok(Some(text.clone())),
            other => anyhow::bail!("bond {name} holds {field} as no text: {other}"),
        }
    };
    let channel = &bond["channel"];
    for (flag, field, value) in [
        ("mode", "mode", &bond["mode"]),
        ("role", "role", &bond["role"]),
        ("token-file", "channel.token_file", &channel["token_file"]),
        ("consumer", "channel.consumer", &channel["consumer"]),
    ] {
        if let Some(value) = text(field, value)? {
            flags.insert(flag.to_string(), value);
        }
    }
    match (
        text("channel.type", &channel["type"])?,
        text("channel.address", &channel["address"])?,
    ) {
        (Some(kind), Some(address)) => {
            flags.insert("channel".to_string(), format!("{kind}:{address}"));
        }
        // Half a channel is no channel `bond add` takes: the edit then needs
        // --channel, and write_bond refuses it without one.
        (_kind, _address) => {}
    }
    match &channel["interval_seconds"] {
        Value::Null => {}
        interval => {
            let seconds = interval.as_u64().with_context(|| {
                format!("bond {name} holds channel.interval_seconds as no whole number of seconds: {interval}")
            })?;
            flags.insert("interval".to_string(), seconds.to_string());
        }
    }
    let peers = match &bond["peers"] {
        Value::Null => Vec::new(),
        Value::Array(peers) => peers
            .iter()
            .map(|peer| {
                peer.as_str().map(str::to_string).with_context(|| {
                    format!("bond {name} holds a peer that is no fingerprint: {peer}")
                })
            })
            .collect::<Result<Vec<String>>>()?,
        other => anyhow::bail!("bond {name} holds its peers as no list: {other}"),
    };
    if !peers.is_empty() {
        flags.insert("peers".to_string(), peers.join(","));
    }
    Ok(flags)
}

/// Checks the flags and writes the bond `name` as they describe it.
fn write_bond(name: &str, flags: &HashMap<String, String>, action: &str) -> Result<Value> {
    let mode = flags.get("mode").or_usage("--mode required")?;
    let role = flags.get("role").or_usage("--role required")?;
    let channel = flags.get("channel").or_usage("--channel required")?;
    if Mode::parse(mode).is_none() {
        anyhow::bail!("mode must be one of: {}", Mode::names());
    }
    if Role::parse(role).is_none() {
        anyhow::bail!("role must be one of: {}", Role::names());
    }
    let (channel_type, address) = channel
        .split_once(':')
        .context("channel must be <type:address>")?;
    let Some(kind) = Channel::parse(channel_type) else {
        anyhow::bail!("channel type must be one of: {}", Channel::names());
    };
    let interval: Option<u64> = flags
        .get("interval")
        .map(|value| {
            value
                .parse::<u64>()
                .or_usage("--interval must be seconds (a number)")
        })
        .transpose()?;
    // No --peers declares no peers.
    let peers: Vec<String> = match flags.get("peers") {
        Some(value) => value.split(',').map(str::to_string).collect(),
        None => Vec::new(),
    };
    // A pulled bond names the owner-only file holding its bearer, never the
    // bearer itself: the bond section is configuration, and the running
    // `serve` reads the file on every pull. The file is read once here so a
    // bond the service could not authenticate with is refused now.
    let token_file = flags.get("token-file").map(|path| path.trim().to_string());
    if let Some(path) = &token_file {
        if kind != Channel::Serve {
            anyhow::bail!(
                "--token-file applies only to a serve channel: only serve channels are pulled"
            );
        }
        if interval.is_none() {
            anyhow::bail!(
                "--token-file requires --interval: serve pulls a bond on the bond's own interval"
            );
        }
        crate::credential::read_secret_file(std::path::Path::new(path))
            .with_context(|| format!("--token-file {path}"))?;
    }
    let consumer = flags.get("consumer");
    if consumer.is_some() && token_file.is_none() {
        anyhow::bail!("--consumer names who pulls and requires --token-file");
    }

    let mut channel_json = json!({"type": channel_type, "address": address});
    if let Some(seconds) = interval {
        channel_json["interval_seconds"] = json!(seconds);
    }
    if let Some(path) = &token_file {
        channel_json["token_file"] = json!(path);
        channel_json["consumer"] = json!(Role::pull_consumer(consumer.map(String::as_str)));
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
            name.to_string(),
            json!({
                "mode": mode,
                "role": role,
                "channel": channel_json,
                "peers": peers,
            }),
        );
    vault.save()?;
    crate::runtime::audit::append(action, &json!({"bond": name, "mode": mode, "role": role}))?;
    Ok(json!({"ok": true, "bond": name, "mode": mode, "role": role}))
}

/// Every configured bond, as the vault holds it. Read-only: a bond that
/// has never pulled still lists, with no pull timestamps.
pub(crate) fn cmd_bond_list() -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    // A vault that never added a bond lists none.
    Ok(match vault.doc().get("bond") {
        Some(bonds) => bonds.clone(),
        None => json!({}),
    })
}

/// Remove one bond by name. A name that is not configured is an error,
/// not a silent success — the caller asked to remove something.
pub(crate) fn cmd_bond_remove(positionals: &[String]) -> Result<Value> {
    let name = positionals.first().or_usage("usage: bond remove <name>")?;
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
    Ok(json!({"ok": true, "bond": name}))
}
