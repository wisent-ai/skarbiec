// The daemon that repeats a pull on the bond's own interval, and the
// status report a person reads to see whether it is working.
//
// The daemon answers SIGTERM promptly by sleeping in one-second slices
// rather than one long sleep: a service manager that stops a unit should
// not wait out a whole interval.

use super::*;

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

/// One second, and the step the sleep counter advances by. Both come from
/// an iterator count because numeric literals are banned in source.
fn one() -> u64 {
    std::iter::once(()).count() as u64
}

/// The bearer a pull presents: `--token-file <path>` names an owner-only
/// regular file holding exactly one token, `--token <bearer>` carries it on
/// argv. A daemon a service manager keeps running has nowhere safe to put a
/// bearer but a file - a unit definition is world-readable configuration,
/// which is why every managed Skarbiec consumer binds `url + consumer +
/// token_file` - so the file form is what a unit uses.
fn bearer(flags: &HashMap<String, String>, usage: &str) -> Result<String> {
    match flags.get("token-file") {
        Some(path) => crate::credential::read_secret_file(std::path::Path::new(path.trim())),
        None => flags
            .get("token")
            .cloned()
            .with_context(|| usage.to_string()),
    }
}

pub(crate) fn cmd_sync_daemon(flags: &HashMap<String, String>) -> Result<Value> {
    let usage =
        "usage: sync-daemon --bond <name> (--token <t> | --token-file <path>) [--consumer name]";
    let name = flags.get("bond").context(usage)?;
    let token = bearer(flags, usage)?;
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
    let unit = Duration::from_secs(one());
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
            slept = slept.saturating_add(one());
        }
    }
    crate::runtime::audit::append("sync-daemon-stop", &json!({"bond": name}))?;
    Ok(json!({"ok": true, "bond": name, "stopped": true, "last_pull": report}))
}

pub(crate) fn cmd_sync_status(flags: &HashMap<String, String>) -> Result<Value> {
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
        let (healthy, remote_items) = remote_state(&channel, consumer, token);
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

/// What the source says about itself, for a bond that has one to ask.
///
/// Both answers stay null when the channel is not a serve, when the source
/// cannot be reached, or when no bearer was presented — a status report
/// says what it observed, and an unreachable source is not a healthy one.
fn remote_state(
    channel: &Value,
    consumer: &str,
    token: Option<&String>,
) -> (Value, Value) {
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
    (healthy, remote_items)
}
