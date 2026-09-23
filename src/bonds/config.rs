// The bond configuration commands: what a bond is, in the vault.
//
// Only non-secret configuration lands here — modes, roles, addresses,
// intervals, peer fingerprints and, for a bond this vault pulls, the path of
// the owner-only file that holds its bearer. A mistyped mode, role or channel
// type is refused against the schema in docs/design/bond.md rather than
// written and discovered later by a replication component that cannot pull.

use super::*;

/// Modes, roles and channel types a bond may declare, from
/// docs/design/bond.md.
const MODES: [&str; 4] = ["replica", "hub", "p2p", "git"];
const ROLES: [&str; 4] = ["source", "replica", "consumer", "peer"];
const CHANNEL_TYPES: [&str; 3] = ["serve", "git", "file"];

pub(crate) fn cmd_bond_add(
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    let name = positionals.first().context(
        "usage: bond-add <name> --mode <mode> --role <role> --channel <type:address> [--peers fpr,fpr] [--interval seconds] [--token-file path [--consumer name]]",
    )?;
    let mode = flags.get("mode").context("--mode required")?;
    let role = flags.get("role").context("--role required")?;
    let channel = flags.get("channel").context("--channel required")?;
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
                .context("--interval must be seconds (a number)")
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
    Ok(json!({"ok": true, "bond": name}))
}
