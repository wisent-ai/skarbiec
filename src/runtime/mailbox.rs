// Private Resend receiving broker for Byk authenticated-login end-to-end tests.
use crate::core::{vault::Vault, vault_path};
use crate::runtime::audit;
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
const COMMAND: &str = "mailbox-broker";
const PROBE: &str = "mailbox-probe";
const KEY: &str = "byk-ios-login";
const PROVIDER: &str = "resend";
const CREDENTIAL: &str = "RESEND_RECEIVING_API_KEY";
const DOMAIN: &str = "wisentmedia.com";
const TEMPLATE: &str = "{{local_part_prefix}}@{{receiving_domain}}";
const LIST_URL: &str = "https://api.resend.com/emails/receiving?limit=20";
const GET_PREFIX: &str = "https://api.resend.com/emails/receiving/";
const OTP_POLICY: &str = "six_to_eight";
const MAX_BUDGET_MS: &str = "90000";
const POLL_SECONDS: &str = "2";
const SOCKET_MODE: &str = "600";
const OCTAL_RADIX: &str = "8";
struct Mailbox {
    key: String,
    recipient: String,
    credential: String,
}
struct Request {
    since: DateTime<Utc>,
    budget: Duration,
}
struct SocketGuard(PathBuf);
enum Failure {
    InvalidRequest,
    InvalidSince,
    StaleSince,
    InvalidBudget,
    ProviderFixed(&'static str),
    InvalidProviderResponse,
    CodeNotFound,
    AmbiguousCode,
    BudgetExpired,
    AuditUnavailable,
    MailboxConfigurationInvalid,
    ProviderCredentialUnavailable,
    ProviderCredentialInvalidShape,
    ProviderHttpStatus(u16),
}
impl Failure {
    fn reason(self) -> String {
        let reason = match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidSince => "invalid_since",
            Self::StaleSince => "since_not_fresh",
            Self::InvalidBudget => "invalid_budget",
            Self::InvalidProviderResponse => "invalid_provider_response",
            Self::CodeNotFound => "code_not_found",
            Self::AmbiguousCode => "ambiguous_code",
            Self::BudgetExpired => "budget_expired",
            Self::AuditUnavailable => "audit_unavailable",
            Self::MailboxConfigurationInvalid => "mailbox_configuration_invalid",
            Self::ProviderCredentialUnavailable => "provider_credential_unavailable",
            Self::ProviderCredentialInvalidShape => "provider_credential_invalid_shape",
            Self::ProviderFixed(reason) => return reason.to_string(),
            Self::ProviderHttpStatus(code) => return format!("provider_http_{code}"),
        };
        reason.to_string()
    }
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn field<'a>(row: &'a Value, name: &str) -> Result<&'a str> {
    row.get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("mailbox catalog field {name} is missing"))
}
fn max_budget() -> Duration {
    Duration::from_millis(MAX_BUDGET_MS.parse().unwrap_or_default())
}
// Every address/decryption control is checked before the vault is opened.
fn load_mailbox(requested: &str) -> Result<Mailbox> {
    if requested != KEY {
        bail!("unsupported mailbox key");
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-mailboxes.json");
    let catalog: Value =
        serde_json::from_str(&fs::read_to_string(path).context("read mailbox catalog")?)
            .context("mailbox catalog is not JSON")?;
    if catalog.get("name").and_then(Value::as_str) != Some("test-mailboxes") {
        bail!("invalid mailbox catalog name");
    }
    let rows = catalog
        .get("mailboxes")
        .and_then(Value::as_array)
        .context("mailbox catalog has no mailboxes array")?;
    let mut found = rows
        .iter()
        .filter(|row| row.get("key").and_then(Value::as_str) == Some(requested));
    let row = found.next().context("mailbox key is not in catalog")?;
    if found.next().is_some() {
        bail!("mailbox key is duplicated in catalog");
    }
    let prefix = field(row, "local_part_prefix")?;
    let domain = field(row, "receiving_domain")?;
    let template = field(row, "address_template")?;
    let credential = field(row, "credential_ref")?;
    if field(row, "provider")? != PROVIDER
        || prefix != KEY
        || domain != DOMAIN
        || template != TEMPLATE
        || credential != CREDENTIAL
    {
        bail!("mailbox catalog contract mismatch");
    }
    let policy = row
        .get("otp_policy")
        .context("mailbox OTP policy is missing")?;
    if policy.get("digits").and_then(Value::as_str) != Some(OTP_POLICY)
        || policy.get("character_set").and_then(Value::as_str) != Some("ascii")
        || policy.get("require_unique").and_then(Value::as_bool) != Some(true)
    {
        bail!("mailbox OTP policy mismatch");
    }
    Ok(Mailbox {
        key: requested.to_string(),
        recipient: template
            .replace("{{local_part_prefix}}", prefix)
            .replace("{{receiving_domain}}", domain),
        credential: credential.to_string(),
    })
}
fn bind_socket(path: &Path) -> Result<(UnixListener, SocketGuard)> {
    if !path.is_absolute() {
        bail!("--socket must be an absolute path");
    }
    if !fs::metadata(path.parent().context("--socket has no parent")?)
        .context("socket parent does not exist")?
        .is_dir()
    {
        bail!("socket parent is not a directory");
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            fs::remove_file(path).context("remove stale socket")?
        }
        Ok(_) => bail!("refusing to replace a non-socket path"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect socket path"),
    }
    let listener = UnixListener::bind(path).context("bind mailbox socket")?;
    let radix = OCTAL_RADIX.parse().context("invalid socket mode radix")?;
    let mode = u32::from_str_radix(SOCKET_MODE, radix).context("invalid socket mode")?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .context("protect mailbox socket")?;
    Ok((listener, SocketGuard(path.to_path_buf())))
}
fn parse_request(line: &[u8], started: DateTime<Utc>) -> std::result::Result<Request, Failure> {
    let value: Value = serde_json::from_slice(line).map_err(|_| Failure::InvalidRequest)?;
    let object = value.as_object().ok_or(Failure::InvalidRequest)?;
    if object.len() != ["since", "budget_ms"].len()
        || !object.contains_key("since")
        || !object.contains_key("budget_ms")
    {
        return Err(Failure::InvalidRequest);
    }
    let since = DateTime::parse_from_rfc3339(
        object
            .get("since")
            .and_then(Value::as_str)
            .ok_or(Failure::InvalidSince)?,
    )
    .map_err(|_| Failure::InvalidSince)?
    .with_timezone(&Utc);
    if since < started || since > Utc::now() {
        return Err(Failure::StaleSince);
    }
    let budget_ms = object
        .get("budget_ms")
        .and_then(Value::as_u64)
        .ok_or(Failure::InvalidBudget)?;
    if budget_ms == u64::default() {
        return Err(Failure::InvalidBudget);
    }
    Ok(Request {
        since,
        budget: Duration::from_millis(budget_ms).min(max_budget()),
    })
}
fn addressed_to(row: &Value, recipient: &str) -> bool {
    row.get("to")
        .and_then(Value::as_array)
        .map(|to| to.iter().any(|v| v.as_str() == Some(recipient)))
        .unwrap_or(false)
}
fn provider_failure(error: ureq::Error) -> Failure {
    let status = |value: &str| value.parse::<u16>().unwrap_or_default();
    let fixed = Failure::ProviderFixed;
    match error {
        ureq::Error::Status(code, _) if code == status("401") || code == status("403") => {
            fixed("provider_auth_rejected")
        }
        ureq::Error::Status(code, _) if code == status("429") => fixed("provider_rate_limited"),
        ureq::Error::Status(code, _) if code == status("404") || code == status("405") => {
            fixed("provider_not_supported")
        }
        ureq::Error::Status(code, _) if code == status("400") => fixed("provider_bad_request"),
        ureq::Error::Status(code, _) if code == status("402") => fixed("provider_payment_required"),
        ureq::Error::Status(code, _) if code == status("406") => fixed("provider_not_acceptable"),
        ureq::Error::Status(code, _) if code == status("422") => {
            fixed("provider_unprocessable_request")
        }
        ureq::Error::Status(code, _) if code < status("500") => fixed("provider_request_rejected"),
        ureq::Error::Status(code, _) if code == status("500") => fixed("provider_internal_error"),
        ureq::Error::Status(code, _) if code == status("502") => fixed("provider_bad_gateway"),
        ureq::Error::Status(code, _) if code == status("503") => {
            fixed("provider_service_unavailable")
        }
        ureq::Error::Status(code, _) if code == status("504") => fixed("provider_gateway_timeout"),
        ureq::Error::Status(code, _) => Failure::ProviderHttpStatus(code),
        ureq::Error::Transport(_) => fixed("provider_transport_failed"),
    }
}
fn get_json(
    agent: &ureq::Agent,
    url: &str,
    auth: &str,
    budget: Duration,
) -> std::result::Result<Value, Failure> {
    let response = agent
        .get(url)
        .set("Authorization", auth)
        .set("Accept", "application/json")
        .timeout(budget)
        .call()
        .map_err(provider_failure)?;
    response
        .into_json()
        .map_err(|_| Failure::InvalidProviderResponse)
}
fn newest_id(
    list: &Value,
    recipient: &str,
    since: DateTime<Utc>,
) -> std::result::Result<Option<String>, Failure> {
    let rows = list
        .get("data")
        .and_then(Value::as_array)
        .ok_or(Failure::InvalidProviderResponse)?;
    let mut newest: Option<(DateTime<Utc>, String)> = None;
    for row in rows {
        if !addressed_to(row, recipient) {
            continue;
        }
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| {
                !id.is_empty()
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            .ok_or(Failure::InvalidProviderResponse)?;
        let created = DateTime::parse_from_rfc3339(
            row.get("created_at")
                .and_then(Value::as_str)
                .ok_or(Failure::InvalidProviderResponse)?,
        )
        .map_err(|_| Failure::InvalidProviderResponse)?
        .with_timezone(&Utc);
        if created >= since && newest.as_ref().map(|(at, _)| created > *at).unwrap_or(true) {
            newest = Some((created, id.to_string()));
        }
    }
    Ok(newest.map(|(_, id)| id))
}
fn extract_code(
    message: &Value,
    id: &str,
    recipient: &str,
    since: DateTime<Utc>,
) -> std::result::Result<String, Failure> {
    if message.get("id").and_then(Value::as_str) != Some(id) || !addressed_to(message, recipient) {
        return Err(Failure::InvalidProviderResponse);
    }
    let created = DateTime::parse_from_rfc3339(
        message
            .get("created_at")
            .and_then(Value::as_str)
            .ok_or(Failure::InvalidProviderResponse)?,
    )
    .map_err(|_| Failure::InvalidProviderResponse)?
    .with_timezone(&Utc);
    if created < since {
        return Err(Failure::InvalidProviderResponse);
    }

    let minimum_width = "000000".chars().count();
    let maximum_width = "00000000".chars().count();
    let codes: HashSet<&str> = ["subject", "text", "html"]
        .iter()
        .filter_map(|key| message.get(key).and_then(Value::as_str))
        .filter(|content| !content.is_empty())
        .flat_map(|content| {
            content
                .split(|character: char| !character.is_ascii_digit())
                .filter(move |run| run.len() >= minimum_width && run.len() <= maximum_width)
        })
        .collect();
    if codes.is_empty() {
        return Err(Failure::CodeNotFound);
    }
    if codes.len() != std::iter::once(()).count() {
        return Err(Failure::AmbiguousCode);
    }
    Ok(codes.into_iter().next().unwrap_or_default().to_string())
}
fn remaining(deadline: Instant) -> std::result::Result<Duration, Failure> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(Failure::BudgetExpired)
}
fn poll(
    agent: &ureq::Agent,
    auth: &str,
    recipient: &str,
    request: &Request,
) -> std::result::Result<String, Failure> {
    let deadline = Instant::now() + request.budget;
    loop {
        let list = get_json(agent, LIST_URL, auth, remaining(deadline)?)?;
        if let Some(id) = newest_id(&list, recipient, request.since)? {
            let message = get_json(
                agent,
                &format!("{GET_PREFIX}{id}"),
                auth,
                remaining(deadline)?,
            )?;
            return extract_code(&message, &id, recipient, request.since);
        }
        let seconds = POLL_SECONDS
            .parse()
            .map_err(|_| Failure::InvalidProviderResponse)?;
        thread::sleep(Duration::from_secs(seconds).min(remaining(deadline)?));
    }
}
fn reply(stream: &mut UnixStream, value: &Value) -> Result<()> {
    serde_json::to_writer(&mut *stream, value)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}
fn handle(
    mut stream: UnixStream,
    mailbox: &Mailbox,
    started_at: DateTime<Utc>,
    agent: &ureq::Agent,
    auth: &str,
) {
    let started = Instant::now();
    let result = (|| {
        let mut line = Vec::new();
        let mut reader = BufReader::new(stream.try_clone().map_err(|_| Failure::InvalidRequest)?);
        if reader
            .read_until(b'\n', &mut line)
            .map_err(|_| Failure::InvalidRequest)?
            == usize::default()
            || !line.ends_with(b"\n")
        {
            return Err(Failure::InvalidRequest);
        }
        poll(
            agent,
            auth,
            &mailbox.recipient,
            &parse_request(&line, started_at)?,
        )
    })();
    let status = if result.is_ok() { "ready" } else { "error" };
    let latency = u64::try_from(started.elapsed().as_millis())
        .unwrap_or_else(|_| max_budget().as_millis() as u64);
    let audited = audit::append(
        COMMAND,
        &json!({
            "mailbox": mailbox.key, "status": status, "latency_ms": latency
        }),
    )
    .map_err(|_| Failure::AuditUnavailable);
    let response = match (result, audited) {
        (Ok(code), Ok(())) => json!({"status": "ready", "code": code}),
        (Err(error), Ok(())) => json!({"status": "error", "reason": error.reason()}),
        (_, Err(error)) => json!({"status": "error", "reason": error.reason()}),
    };
    if reply(&mut stream, &response).is_err() {
        eprintln!("mailbox-broker: socket response failed");
    }
}
fn decrypt_value(id: &str) -> Result<String> {
    let vault = Vault::open(vault_path())?;
    let item = Vault::get_item(&vault, id).context("decrypt mailbox provider credential")?;
    let mut normalized = item
        .get("value")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context("mailbox provider credential has no value field")?
        .to_string();
    if let Ok(wrapper) = serde_json::from_str::<Value>(&normalized) {
        normalized = match wrapper {
            Value::String(value) => value,
            Value::Object(object) if object.len() == std::iter::once(()).count() => object
                .get(id)
                .and_then(Value::as_str)
                .map(str::to_string)
                .context("mailbox provider credential has invalid shape")?,
            _ => bail!("mailbox provider credential has invalid shape"),
        };
    }
    let mut value = normalized.trim();
    let exported = value.strip_prefix("export ");
    let had_export = exported.is_some();
    value = exported.unwrap_or(value).trim();
    let assignment = format!("{id}=");
    if let Some(assigned) = value.strip_prefix(&assignment) {
        value = assigned.trim();
    } else if had_export {
        bail!("mailbox provider credential has invalid shape");
    }
    value = value
        .strip_prefix('\'')
        .and_then(|inner| inner.strip_suffix('\''))
        .or_else(|| {
            value
                .strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
        })
        .unwrap_or(value)
        .trim();
    let suffix = value
        .strip_prefix("re_")
        .filter(|suffix| !suffix.is_empty())
        .context("mailbox provider credential has invalid shape")?;
    if !suffix
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        bail!("mailbox provider credential has invalid shape");
    }
    Ok(value.to_string())
}
fn provider_credential(id: &str) -> std::result::Result<String, Failure> {
    decrypt_value(id).map_err(|error| {
        if error.to_string() == "mailbox provider credential has invalid shape" {
            Failure::ProviderCredentialInvalidShape
        } else {
            Failure::ProviderCredentialUnavailable
        }
    })
}
fn probe(flags: &HashMap<String, String>, positionals: &[String]) -> Value {
    let outcome = (|| -> std::result::Result<(), Failure> {
        if !positionals.is_empty()
            || flags.len() != ["mailbox"].len()
            || flags.get("mailbox").map(String::as_str) != Some(KEY)
        {
            return Err(Failure::InvalidRequest);
        }
        let mailbox = load_mailbox(KEY).map_err(|_| Failure::MailboxConfigurationInvalid)?;
        let api_key = provider_credential(&mailbox.credential)?;
        let auth = format!("Bearer {api_key}");
        let agent = ureq::AgentBuilder::new().redirects(u32::default()).build();
        let list = get_json(&agent, LIST_URL, &auth, max_budget())?;
        list.get("data")
            .and_then(Value::as_array)
            .ok_or(Failure::InvalidProviderResponse)?;
        Ok(())
    })();
    let status = if outcome.is_ok() { "ready" } else { "error" };
    let audited = audit::append(PROBE, &json!({"mailbox": KEY, "status": status})).is_ok();
    match (outcome, audited) {
        (Ok(()), true) => json!({"status": "ready", "mailbox": KEY}),
        (Err(error), true) => json!({"status": "error", "reason": error.reason()}),
        (_, false) => json!({"status": "error", "reason": Failure::AuditUnavailable.reason()}),
    }
}
fn serve(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    if !positionals.is_empty() || flags.len() != ["mailbox", "socket"].len() {
        bail!("usage: mailbox-broker --mailbox <key> --socket <absolute-path>");
    }
    let key = flags
        .get("mailbox")
        .filter(|v| !v.is_empty())
        .context("missing --mailbox")?;
    let path = flags
        .get("socket")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .context("missing --socket")?;
    let mailbox = load_mailbox(key)
        .map_err(|_| anyhow::anyhow!(Failure::MailboxConfigurationInvalid.reason()))?;
    let (listener, _guard) = bind_socket(&path)?;
    let api_key = provider_credential(&mailbox.credential)
        .map_err(|failure| anyhow::anyhow!(failure.reason()))?;
    let auth = format!("Bearer {api_key}");
    let agent = ureq::AgentBuilder::new().redirects(u32::default()).build();
    let started_at = Utc::now();
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(
        &mut stdout,
        &json!({"status": "ready", "socket_path": path, "mailbox": mailbox.key, "recipient": mailbox.recipient}),
    )?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    drop(stdout);
    loop {
        let (stream, _) = listener.accept().context("accept mailbox socket client")?;
        handle(stream, &mailbox, started_at, &agent, &auth);
    }
}
pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command == PROBE {
        return Ok(Some(probe(flags, positionals)));
    }
    if command != COMMAND {
        return Ok(None);
    }
    serve(flags, positionals)?;
    Ok(None)
}
