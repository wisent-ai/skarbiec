// Replication as one pull per pulled bond, and the status report a person
// reads to see whether it is working.
//
// A bond whose serve channel records a bearer file (`bond add --token-file`)
// is a bond this vault pulls. `skarbiec maintain` pulls each such bond once;
// a Stado schedule pinned to the replica host decides how often. A failed
// pull goes to stderr and to the audit journal as `replication-failed`, and
// the pass reports it.

use super::*;

/// The bonds this vault pulls: serve channels that record a bearer file and an
/// interval. Another bond (this vault as a source, a git or a file channel) is
/// not replication work. A host with no vault yet pulls nothing.
pub(crate) fn pulled_bonds() -> Result<Vec<String>> {
    let path = vault_path();
    if !path
        .try_exists()
        .with_context(|| format!("inspect replication vault {}", path.display()))?
    {
        return Ok(Vec::new());
    }
    Ok(pulled(Vault::open(path)?.doc()))
}

fn pulled(doc: &Value) -> Vec<String> {
    doc.get("bond")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(_, entry)| {
            let channel = entry.get("channel");
            let field = |key: &str| channel.and_then(|c| c.get(key));
            field("type")
                .and_then(Value::as_str)
                .and_then(Channel::parse)
                == Some(Channel::Serve)
                && field("token_file").and_then(Value::as_str).is_some()
                && field("interval_seconds").and_then(Value::as_u64).is_some()
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// Pull one bond with the bearer its file holds now, so a rotated file is
/// used without a restart. A refused or failed pull is journalled as
/// `replication-failed` and returned as the error.
fn pull(name: &str, address: &str, token_file: &str, consumer: &str) -> Result<()> {
    let flags = HashMap::from([
        ("from".to_string(), address.to_string()),
        ("token-file".to_string(), token_file.to_string()),
        ("consumer".to_string(), consumer.to_string()),
        ("bond".to_string(), name.to_string()),
    ]);
    let outcome = crate::net::bond::cmd_pull(&flags);
    let failure = match outcome {
        Ok(report) if report.get("ok").and_then(Value::as_bool) == Some(true) => return Ok(()),
        Ok(report) => report.to_string(),
        Err(error) => format!("{error:#}"),
    };
    crate::runtime::audit::append(
        "replication-failed",
        &json!({"bond": name, "address": address, "detail": failure}),
    )
    .with_context(|| {
        format!(
            "bond {name} did not pull from {address}: {failure}; record replication-failed audit"
        )
    })?;
    anyhow::bail!("bond {name} did not pull from {address}: {failure}")
}

/// Pull the named bond once with the bearer its file holds now.
pub(crate) fn pull_once(name: &str) -> Result<()> {
    let vault = Vault::open(vault_path())?;
    let channel = vault
        .doc()
        .get("bond")
        .and_then(|bonds| bonds.get(name))
        .and_then(|bond| bond.get("channel"))
        .with_context(|| format!("no bond named: {name}"))?;
    let text = |key: &str| channel.get(key).and_then(Value::as_str).map(str::to_string);
    let address = text("address").with_context(|| format!("bond {name} channel has no address"))?;
    let token_file = text("token_file").with_context(|| {
        format!("bond {name} records no token_file (set it with bond edit {name} --token-file)")
    })?;
    let consumer = Role::pull_consumer(text("consumer").as_deref()).to_string();
    drop(vault);
    pull(name, &address, &token_file, &consumer)
}

pub(crate) fn cmd_sync_status(flags: &HashMap<String, String>) -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    // A vault that never added a bond has no bond section; one whose section
    // is not an object was written wrong, and is said so.
    let bonds = match vault.doc().get("bond") {
        None => serde_json::Map::new(),
        Some(Value::Object(bonds)) => bonds.clone(),
        Some(other) => anyhow::bail!("the vault's bond section is not an object: {other}"),
    };
    let pulled_by_service = pulled(vault.doc());
    // Null when the vault holds no items map, rather than a count of zero.
    let local_count = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .map(serde_json::Map::len);
    let wanted = flags.get("bond");
    if flags.contains_key("token") {
        anyhow::bail!(
            "bond status does not take --token: a bearer in argv is readable by every process on this host. \
             Write it to an owner-only file (mode 0600) and pass --token-file <absolute path>"
        );
    }
    // An explicitly named bearer file is the operator's word: one that cannot
    // be read fails the command instead of falling back to the bond's own.
    let explicit = flags
        .get("token-file")
        .map(|path| crate::credential::read_secret_file(std::path::Path::new(path.trim())))
        .transpose()?;
    let mut out = Vec::new();
    for (name, entry) in &bonds {
        if wanted.is_some_and(|w| w != name) {
            continue;
        }
        let channel = entry.get("channel");
        let consumer =
            Role::pull_consumer(flags.get("consumer").map(String::as_str).or_else(|| {
                channel
                    .and_then(|c| c.get("consumer"))
                    .and_then(Value::as_str)
            }));
        // An explicit bearer file wins. Otherwise the report reads the bond's
        // own bearer file, the one the running service pulls with, so a file
        // the service cannot read appears here with the error the service meets.
        let (token, token_file_error) = match &explicit {
            Some(token) => (Some(token.clone()), Value::Null),
            None => match channel
                .and_then(|c| c.get("token_file"))
                .and_then(Value::as_str)
            {
                Some(file) => match crate::credential::read_secret_file(std::path::Path::new(file))
                {
                    Ok(token) => (Some(token), Value::Null),
                    Err(error) => (None, json!(format!("{error:#}"))),
                },
                None => (None, Value::Null),
            },
        };
        let remote = remote_state(channel, consumer, token.as_ref());
        out.push(json!({
            "bond": name,
            "mode": entry.get("mode"),
            "role": entry.get("role"),
            "channel": channel,
            "pulled_by_service": pulled_by_service.contains(name),
            "token_file_error": token_file_error,
            "last_pull_at": entry.get("last_pull_at"),
            "last_items_after": entry.get("last_items_after"),
            "local_items": local_count,
            "remote_items": remote.items,
            "healthy": remote.healthy,
            "remote_errors": remote.errors,
        }));
    }
    Ok(json!(out))
}

/// What the source says about itself, for a bond that has one to ask.
struct Remote {
    healthy: Option<Value>,
    items: Option<usize>,
    /// Why an answer above is null: the request that failed, or the answer
    /// that carried no such field, each with its cause.
    errors: Vec<String>,
}

/// Both answers stay null when the channel is not a serve or when no bearer
/// was presented. A source that was asked and did not answer is null with its
/// cause in `errors`: an unreachable source is not a healthy one, and a null
/// without its reason reads the same as a source nobody asked.
fn remote_state(channel: Option<&Value>, consumer: &str, token: Option<&String>) -> Remote {
    let mut remote = Remote {
        healthy: None,
        items: None,
        errors: Vec::new(),
    };
    let channel_type = channel.and_then(|c| c.get("type")).and_then(Value::as_str);
    if channel_type.and_then(Channel::parse) != Some(Channel::Serve) {
        return remote;
    }
    let Some(address) = channel
        .and_then(|c| c.get("address"))
        .and_then(Value::as_str)
    else {
        remote
            .errors
            .push("the serve channel records no address".to_string());
        return remote;
    };
    match crate::net::serve::serve_request(address, "GET", "/health", "", "", None) {
        Ok((status, health)) => match health.get("ok") {
            Some(ok) => remote.healthy = Some(ok.clone()),
            None => remote.errors.push(format!(
                "GET /health answered {status} without ok: {health}"
            )),
        },
        Err(error) => remote.errors.push(format!("{error:#}")),
    }
    if let Some(presented) = token {
        match crate::net::serve::serve_request(
            address,
            "GET",
            "/v1/vault",
            consumer,
            presented,
            None,
        ) {
            Ok((status, doc)) => match doc.get("items").and_then(Value::as_object) {
                Some(items) => remote.items = Some(items.len()),
                None => remote.errors.push(format!(
                    "GET /v1/vault answered {status} without items: {doc}"
                )),
            },
            Err(error) => remote.errors.push(format!("{error:#}")),
        }
    }
    remote
}
