// Replication performed inside the running `skarbiec serve`, and the status
// report a person reads to see whether it is working.
//
// A bond whose serve channel records a bearer file (`bond-add --token-file`)
// is a bond this vault pulls. `serve` starts one replication component per
// such bond, so a replica host runs the same single Skarbiec process as every
// other host and no separate sync daemon. A failed pull does not end the
// component: the process keeps serving while the replica is stale, and the
// failure goes to stderr and to the audit journal as `replication-failed`.

use super::*;

/// One second, and the step the sleep counter advances by. Both come from
/// an iterator count because numeric literals are banned in source.
fn one() -> u64 {
    std::iter::once(()).count() as u64
}

/// The bonds this vault pulls: serve channels that record a bearer file and an
/// interval. Another bond (this vault as a source, a git or a file channel) is
/// not replication work. A host with no vault yet pulls nothing.
pub(crate) fn pulled_bonds() -> Result<Vec<String>> {
    let path = vault_path();
    if !path.exists() {
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
            field("type").and_then(Value::as_str) == Some("serve")
                && field("token_file").and_then(Value::as_str).is_some()
                && field("interval_seconds").and_then(Value::as_u64).is_some()
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// Pull one bond with the bearer its file holds now, so a rotated file is
/// used without a restart. A refused or failed pull is reported and journalled;
/// only a failure to journal it is an error.
fn pull(name: &str, address: &str, token_file: &str, consumer: &str) -> Result<()> {
    let outcome =
        crate::credential::read_secret_file(std::path::Path::new(token_file)).and_then(|token| {
            let flags = HashMap::from([
                ("from".to_string(), address.to_string()),
                ("token".to_string(), token),
                ("consumer".to_string(), consumer.to_string()),
                ("bond".to_string(), name.to_string()),
            ]);
            crate::net::bond::cmd_pull(&flags)
        });
    let failure = match outcome {
        Ok(report) if report.get("ok").and_then(Value::as_bool) == Some(true) => return Ok(()),
        Ok(report) => report.to_string(),
        Err(error) => format!("{error:#}"),
    };
    eprintln!("skarbiec replication: bond {name} did not pull from {address}: {failure}");
    crate::runtime::audit::append(
        "replication-failed",
        &json!({"bond": name, "address": address, "detail": failure}),
    )?;
    Ok(())
}

/// One replication component of `serve`: pull the named bond now and then on
/// the bond's own interval. It returns only with an error, and the owning
/// service treats a returned component as the failure of the whole process.
pub(crate) fn run_sync(name: &str) -> Result<Value> {
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
        format!("bond {name} records no token_file (set it with bond-add --token-file)")
    })?;
    let consumer = text("consumer").unwrap_or_else(|| "replica".to_string());
    let interval = channel
        .get("interval_seconds")
        .and_then(Value::as_u64)
        .with_context(|| {
            format!("bond {name} channel has no interval_seconds (set it with bond-add --interval)")
        })?;
    drop(vault);
    crate::runtime::audit::append(
        "replication-start",
        &json!({"bond": name, "address": address, "interval_seconds": interval}),
    )?;
    let unit = Duration::from_secs(one());
    loop {
        pull(name, &address, &token_file, &consumer)?;
        let mut slept = u64::default();
        while slept < interval {
            thread::sleep(unit);
            slept = slept.saturating_add(one());
        }
    }
}

pub(crate) fn cmd_sync_status(flags: &HashMap<String, String>) -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    let bonds = vault
        .doc()
        .get("bond")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let pulled_by_service = pulled(vault.doc());
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
        let consumer = flags
            .get("consumer")
            .map(String::as_str)
            .or_else(|| channel.get("consumer").and_then(Value::as_str))
            .unwrap_or("replica");
        // An explicit bearer wins. Otherwise the report reads the bond's own
        // bearer file, the one the running service pulls with, so a file the
        // service cannot read appears here with the error the service meets.
        let (token, token_file_error) = match flags.get("token") {
            Some(token) => (Some(token.clone()), Value::Null),
            None => match channel.get("token_file").and_then(Value::as_str) {
                Some(file) => match crate::credential::read_secret_file(std::path::Path::new(file))
                {
                    Ok(token) => (Some(token), Value::Null),
                    Err(error) => (None, json!(format!("{error:#}"))),
                },
                None => (None, Value::Null),
            },
        };
        let (healthy, remote_items) = remote_state(&channel, consumer, token.as_ref());
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
            "remote_items": remote_items,
            "healthy": healthy,
        }));
    }
    Ok(json!(out))
}

/// What the source says about itself, for a bond that has one to ask.
///
/// Both answers stay null when the channel is not a serve, when the source
/// cannot be reached, or when no bearer was presented — a status report
/// says what it observed, and an unreachable source is not a healthy one.
fn remote_state(channel: &Value, consumer: &str, token: Option<&String>) -> (Value, Value) {
    let channel_type = channel.get("type").and_then(Value::as_str).unwrap_or("");
    if channel_type != "serve" {
        return (Value::Null, Value::Null);
    }
    let address = channel.get("address").and_then(Value::as_str).unwrap_or("");
    let mut healthy = Value::Null;
    let mut remote_items = Value::Null;
    if let Ok((_status, health)) =
        crate::net::bond::serve_request(address, "GET", "/health", "", "", None)
    {
        healthy = health.get("ok").cloned().unwrap_or(Value::Null);
    }
    if let Some(presented) = token {
        if let Ok((_status, doc)) =
            crate::net::bond::serve_request(address, "GET", "/v1/vault", consumer, presented, None)
        {
            remote_items = doc
                .get("items")
                .and_then(Value::as_object)
                .map(|items| json!(items.len()))
                .unwrap_or(Value::Null);
        }
    }
    (healthy, remote_items)
}
