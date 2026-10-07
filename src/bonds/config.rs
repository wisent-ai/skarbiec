// The bond configuration commands: what a bond is, in the vault.
//
// Only non-secret configuration lands here — modes, roles, addresses,
// intervals, peer fingerprints and, for a bond this vault pulls, the path of
// the owner-only file that holds its bearer. A mistyped mode, role or channel
// type is refused against the schema in docs/design/bond.md rather than
// written and discovered later by a pull that cannot run.

use super::*;
use crate::cli::args::OrUsage;

/// Modes, roles and channel types a bond may declare, from
/// docs/design/bond.md.
const MODES: [&str; 4] = ["replica", "hub", "p2p", "git"];
const ROLES: [&str; 4] = ["source", "replica", "consumer", "peer"];
const CHANNEL_TYPES: [&str; 3] = ["serve", "git", "file"];

/// A new bond. A name already configured is refused with its mode and role;
/// `bond-edit` changes it.
pub(crate) fn cmd_bond_add(
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    let name = positionals.first().or_usage(
        "usage: bond-add <name> --mode <mode> --role <role> --channel <type:address> [--peers fpr,fpr] [--interval seconds] [--token-file path [--consumer name]]",
    )?;
    let vault = Vault::open(vault_path())?;
    if let Some(existing) = vault.doc().get("bond").and_then(|bonds| bonds.get(name)) {
        anyhow::bail!(
            "bond {name} is already configured (mode {}, role {}); `skarbiec bond-edit {name}` changes it",
            existing["mode"].as_str().unwrap_or("-"),
            existing["role"].as_str().unwrap_or("-"),
        );
    }
    drop(vault);
    write_bond(name, flags, "bond-add")
}

/// Change one configured bond: every flag `bond-add` takes may be given,
/// and what is not given keeps its configured value. The result passes the
/// same checks a new bond does.
pub(crate) fn cmd_bond_edit(
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    let name = positionals.first().or_usage(
        "usage: bond-edit <name> [--mode <mode>] [--role <role>] [--channel <type:address>] [--peers fpr,fpr] [--interval seconds] [--token-file path [--consumer name]]",
    )?;
    if flags.is_empty() {
        anyhow::bail!("bond-edit changes nothing without a flag `bond-add` takes");
    }
    let vault = Vault::open(vault_path())?;
    let current = vault
        .doc()
        .get("bond")
        .and_then(|bonds| bonds.get(name))
        .cloned()
        .with_context(|| format!("no bond named: {name}; `skarbiec bond-list` lists them"))?;
    drop(vault);
    let mut merged = configured_flags(&current);
    merged.extend(
        flags
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    write_bond(name, &merged, "bond-edit")
}

/// The flags `bond-add` would take to configure `bond` as it stands.
fn configured_flags(bond: &Value) -> HashMap<String, String> {
    let mut flags = HashMap::new();
    let mut keep = |key: &str, value: Option<String>| {
        if let Some(value) = value {
            flags.insert(key.to_string(), value);
        }
    };
    let text = |value: &Value| value.as_str().map(str::to_string);
    let channel = &bond["channel"];
    keep("mode", text(&bond["mode"]));
    keep("role", text(&bond["role"]));
    keep(
        "channel",
        text(&channel["type"])
            .zip(text(&channel["address"]))
            .map(|(kind, address)| format!("{kind}:{address}")),
    );
    keep(
        "interval",
        channel["interval_seconds"]
            .as_u64()
            .map(|seconds| seconds.to_string()),
    );
    keep("token-file", text(&channel["token_file"]));
    keep("consumer", text(&channel["consumer"]));
    let peers: Vec<String> = bond["peers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(text)
        .collect();
    if !peers.is_empty() {
        keep("peers", Some(peers.join(",")));
    }
    flags
}

/// Checks the flags and writes the bond `name` as they describe it.
fn write_bond(name: &str, flags: &HashMap<String, String>, action: &str) -> Result<Value> {
    let mode = flags.get("mode").or_usage("--mode required")?;
    let role = flags.get("role").or_usage("--role required")?;
    let channel = flags.get("channel").or_usage("--channel required")?;
    if !MODES.contains(&mode.as_str()) {
        anyhow::bail!("mode must be one of: {}", MODES.join(", "));
    }
    if !ROLES.contains(&role.as_str()) {
        anyhow::bail!("role must be one of: {}", ROLES.join(", "));
    }
    let (channel_type, address) = channel
        .split_once(':')
        .context("channel must be <type:address>")?;
    if !CHANNEL_TYPES.contains(&channel_type) {
        anyhow::bail!("channel type must be one of: {}", CHANNEL_TYPES.join(", "));
    }
    let interval: Option<u64> = flags
        .get("interval")
        .map(|value| {
            value
                .parse::<u64>()
                .or_usage("--interval must be seconds (a number)")
        })
        .transpose()?;
    let peers: Vec<String> = flags
        .get("peers")
        .map(|value| value.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    // A pulled bond names the owner-only file holding its bearer, never the
    // bearer itself: the bond section is configuration, and the running
    // `serve` reads the file on every pull. The file is read once here so a
    // bond the service could not authenticate with is refused now.
    let token_file = flags.get("token-file").map(|path| path.trim().to_string());
    if let Some(path) = &token_file {
        if channel_type != "serve" {
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
        channel_json["consumer"] = json!(consumer.map(String::as_str).unwrap_or("replica"));
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
    Ok(vault
        .doc()
        .get("bond")
        .cloned()
        .unwrap_or_else(|| json!({})))
}

/// Remove one bond by name. A name that is not configured is an error,
/// not a silent success — the caller asked to remove something.
pub(crate) fn cmd_bond_remove(positionals: &[String]) -> Result<Value> {
    let name = positionals.first().or_usage("usage: bond-remove <name>")?;
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
