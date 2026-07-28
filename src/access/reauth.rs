//! Provider credential reauth-on-redeem. When a redeemed provider credential is
//! expired, the broker asks Weles to reauthenticate, waits for Weles to update
//! the capability-backed vault entry out of band, then re-reads the vault and
//! returns the fresh scalar. Provider OAuth refresh is deliberately absent:
//! only Brama's scoped provider runtime may contact provider token endpoints.
//! The wait is bounded by SKARBIEC_REAUTH_WAIT_MS so the synchronous redeem
//! handler never blocks upstream callers for the length of a browser login;
//! when the budget runs out the original secret is served and a later redeem
//! picks up the refreshed entry. Plaintext credentials in a Weles response are
//! never accepted or persisted; `refreshed: true` is only a signal to re-read
//! the vault. Failures degrade to the original secret and never break
//! redemption. No secret material is logged.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::RngCore;
use zeroize::Zeroize;

const EXPIRY_MARGIN_SECONDS: i64 = 60;
const REAUTH_DEBOUNCE_SECONDS: u64 = 120;
const DEFAULT_REAUTH_TIMEOUT_MS: u64 = 300_000;
const DEFAULT_REAUTH_WAIT_MS: u64 = 5_000;
const RUN_POLL_INTERVAL: Duration = Duration::from_secs(5);
const STADO_PULL_TIMEOUT_MS: u64 = 30_000;
const STADO_PUSH_TIMEOUT_MS: u64 = 10_000;
const EXPIRY_KEYS: [&str; 4] = ["expiresAt", "expires_at", "expires", "expiry"];

/// True when the secret carries an expiry that is now or arrives within the
/// margin. Plain strings, non-JSON, and objects without an expiry field are
/// treated as non-expiring.
fn credential_expiry(secret: &str) -> Option<i64> {
    let value: Value = serde_json::from_str(secret).ok()?;
    let object = value.as_object()?;
    expiry_field(object).or_else(|| {
        object
            .values()
            .filter_map(Value::as_object)
            .find_map(expiry_field)
    })
}

#[cfg(test)]
fn credential_expired(secret: &str) -> bool {
    credential_expiry(secret)
        .map(|expiry| now_seconds() + EXPIRY_MARGIN_SECONDS >= expiry)
        .unwrap_or(false)
}

fn expiry_field(object: &serde_json::Map<String, Value>) -> Option<i64> {
    EXPIRY_KEYS
        .iter()
        .find_map(|key| object.get(*key).and_then(expiry_epoch_seconds))
}

fn expiry_epoch_seconds(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_f64().map(normalize_epoch),
        Value::String(text) => {
            let text = text.trim();
            if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(text) {
                return Some(parsed.timestamp());
            }
            text.parse::<i64>().ok().map(|epoch| normalize_epoch(epoch as f64))
        }
        _ => None,
    }
}

/// Epoch milliseconds passed 1e11 in 1973; epoch seconds only will in 5138.
fn normalize_epoch(epoch: f64) -> i64 {
    if epoch.abs() >= 100_000_000_000.0 {
        (epoch / 1_000.0) as i64
    } else {
        epoch as i64
    }
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

/// Maps a `provider:<provider>:<subscription>` resource to the Weles provider
/// name; only providers with a Weles reauth trajectory are reauthable.
fn weles_provider_for_resource(resource: &str) -> Option<&'static str> {
    let mut parts = resource.splitn(3, ':');
    let scheme = parts.next()?;
    let provider = parts.next()?;
    let subscription = parts.next()?;
    if scheme != "provider" || subscription.is_empty() {
        return None;
    }
    match provider {
        "claude-code" => Some("claude"),
        "codex" => Some("codex"),
        "kimi" => Some("kimi"),
        _ => None,
    }
}

fn env_non_empty(names: &[&str]) -> Option<String> {
    names
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
}

fn explicit_reauth_url() -> Option<String> {
    env_non_empty(&[
        "SKARBIEC_REAUTH_URL",
        "WELES_BRAMA_REAUTH_URL",
        "WELES_REAUTH_URL",
    ])
}

fn runs_api_url() -> Result<String, String> {
    let base = env_non_empty(&["WELES_URL"]).ok_or_else(|| "reauth not configured".to_string())?;
    Ok(format!("{}/api/v1/runs", base.trim_end_matches('/')))
}

fn reauth_token() -> Option<String> {
    env_non_empty(&["BRAMA_WELES_REAUTH_TOKEN"])
}

fn reauth_timeout() -> Duration {
    let ms = std::env::var("SKARBIEC_REAUTH_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .unwrap_or(DEFAULT_REAUTH_TIMEOUT_MS);
    Duration::from_millis(ms)
}

/// Caller patience for one redeem: total time the hook may spend inside the
/// Weles call + polling before falling back to the original (expired) secret.
fn reauth_wait() -> Duration {
    let ms = std::env::var("SKARBIEC_REAUTH_WAIT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .unwrap_or(DEFAULT_REAUTH_WAIT_MS);
    Duration::from_millis(ms)
}

/// No agent-level timeout: every request carries its own budget-derived
/// per-request timeout so a blocking read can never outlive the wait budget.
fn reauth_agent() -> ureq::Agent {
    ureq::AgentBuilder::new().redirects(u32::default()).build()
}

fn http_failure(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(code, _) => format!("weles reauth returned HTTP {code}"),
        ureq::Error::Transport(_) => "weles reauth transport failure".to_string(),
    }
}

/// True when a Weles response claims the vault entry was refreshed.
fn response_claims_refresh(body: &Value) -> bool {
    body.get("refreshed").and_then(Value::as_bool) == Some(true)
        || body.get("updated").and_then(Value::as_bool) == Some(true)
        || body
            .get("subscription")
            .and_then(|subscription| subscription.get("status"))
            .and_then(Value::as_str)
            == Some("active")
}

/// Trust contract: a reauth response must never carry plaintext credentials.
/// Scans recursively so nested objects and arrays cannot smuggle one through.
fn contains_credential_field(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "credential" | "credentials" | "api_key" | "apiKey" | "token" | "key"
            ) || contains_credential_field(value)
        }),
        Value::Array(values) => values.iter().any(contains_credential_field),
        _ => false,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RunState {
    Refreshed,
    Running,
}

/// Evaluates a create/poll response body: plaintext credentials are rejected
/// outright, terminal failures error, success requires refresh evidence, and
/// anything else means the run is still in flight.
fn completed_reauth_result(body: &Value) -> Result<RunState, String> {
    if contains_credential_field(body) {
        return Err("Weles reauth returned forbidden plaintext credential".to_string());
    }
    let status = body.get("status").and_then(Value::as_str).unwrap_or("");
    if matches!(status, "failed" | "error" | "cancelled" | "canceled") {
        return Err("Weles reauth run failed".to_string());
    }
    if !matches!(status, "completed" | "succeeded" | "success" | "done") {
        return Ok(RunState::Running);
    }
    if response_claims_refresh(body) || body.get("result").is_some() {
        return Ok(RunState::Refreshed);
    }
    Err("Weles reauth run completed without result evidence".to_string())
}

#[cfg(test)]
/// Legacy shape fixture retained only for embedded compatibility tests.
struct DirectProvider {
    token_endpoint: &'static str,
    client_id: &'static str,
    form: bool,
}

/// Direct refresh config, keyed by the Weles provider name (after the
/// resource mapping). Only these three providers refresh directly.
#[cfg(test)]
fn direct_provider(provider: &str) -> Option<DirectProvider> {
    match provider {
        "claude" | "codex" | "kimi" => Some(DirectProvider {
            token_endpoint: "",
            client_id: "",
            form: false,
        }),
        _ => None,
    }
}

/// Location of the refresh token inside each provider's vault blob.
#[cfg(test)]
fn direct_refresh_token<'a>(blob: &'a Value, provider: &str) -> Option<&'a str> {
    let value = match provider {
        "claude" => blob.get("claudeAiOauth")?.get("refreshToken")?,
        "codex" => blob.get("tokens")?.get("refresh_token")?,
        "kimi" => blob.get("refresh_token")?,
        _ => return None,
    };
    value.as_str().filter(|token| !token.is_empty())
}

#[cfg(test)]
struct RefreshGrant {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_in: Option<u64>,
}


/// Patches the provider blob with the fresh grant, preserving every unrelated
/// field; expiry is written in the blob's own field and units (claude
/// `expiresAt` epoch-ms, kimi `expires_at` epoch-s, codex `last_refresh`
/// RFC3339 when the field already exists). Returns false when the blob does
/// not match the provider's expected shape.
#[cfg(test)]
fn patch_blob(blob: &mut Value, provider: &str, grant: &RefreshGrant, now: i64) -> bool {
    match provider {
        "claude" => {
            let Some(oauth) = blob.get_mut("claudeAiOauth").and_then(Value::as_object_mut) else {
                return false;
            };
            oauth.insert("accessToken".to_string(), json!(grant.access_token));
            if let Some(token) = &grant.refresh_token {
                oauth.insert("refreshToken".to_string(), json!(token));
            }
            if let Some(expires_in) = grant.expires_in {
                oauth.insert(
                    "expiresAt".to_string(),
                    json!((now + expires_in as i64) * 1_000),
                );
            }
            true
        }
        "codex" => {
            {
                let Some(tokens) = blob.get_mut("tokens").and_then(Value::as_object_mut) else {
                    return false;
                };
                tokens.insert("access_token".to_string(), json!(grant.access_token));
                if let Some(token) = &grant.refresh_token {
                    tokens.insert("refresh_token".to_string(), json!(token));
                }
                if let Some(token) = &grant.id_token {
                    tokens.insert("id_token".to_string(), json!(token));
                }
            }
            if blob.get("last_refresh").is_some() {
                if let Some(stamp) =
                    chrono::DateTime::from_timestamp(now, 0).map(|at| at.to_rfc3339())
                {
                    blob["last_refresh"] = json!(stamp);
                }
            }
            true
        }
        "kimi" => {
            let Some(fields) = blob.as_object_mut() else {
                return false;
            };
            fields.insert("access_token".to_string(), json!(grant.access_token));
            if let Some(token) = &grant.refresh_token {
                fields.insert("refresh_token".to_string(), json!(token));
            }
            if let Some(expires_in) = grant.expires_in {
                fields.insert("expires_at".to_string(), json!(now + expires_in as i64));
            }
            true
        }
        _ => false,
    }
}

#[cfg(test)]
fn try_direct_refresh_at(
    _config: &DirectProvider,
    _vault_path: &Path,
    _resource: &str,
    _provider: &str,
    _secret: &str,
    _wait: Duration,
) -> Option<String> {
    None
}


/// Asks Weles to reauthenticate the provider, bounded by `wait`. Ok(Some(true))
/// only when Weles confirms an out-of-band vault refresh; Ok(Some(false)) when
/// it answers without a refresh claim; Ok(None) when the wait budget ran out
/// while the reauth is still in progress server-side. Response bodies are
/// otherwise discarded and never persisted or logged. Direct mode when an
/// explicit reauth URL is configured, Weles runs API otherwise.
fn trigger_weles_reauth(
    provider: &str,
    resource: &str,
    credential_expiry: i64,
    wait: Duration,
) -> Result<Option<bool>, String> {
    match explicit_reauth_url() {
        Some(url) => direct_reauth(&url, provider, resource, wait),
        None => runs_api_reauth(provider, resource, credential_expiry, wait),
    }
}

fn direct_reauth(
    url: &str,
    provider: &str,
    resource: &str,
    wait: Duration,
) -> Result<Option<bool>, String> {
    let budget = reauth_timeout().min(wait);
    let mut request = reauth_agent().post(url).set("Accept", "application/json");
    if let Some(token) = reauth_token() {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    if let Some(secret) = env_non_empty(&["WELES_REAUTH_SECRET"]) {
        request = request.set("x-weles-reauth-secret", &secret);
    }
    let body = json!({
        "source": "skarbiec",
        "reason": "credential_expired",
        "provider": provider,
        "resource": resource,
        "requested_at": chrono::Utc::now().to_rfc3339(),
    });
    let response = request.timeout(budget).send_json(body).map_err(http_failure)?;
    let body: Value = response
        .into_json()
        .map_err(|_| "weles reauth response is not JSON".to_string())?;
    Ok(Some(response_claims_refresh(&body)))
}

/// Weles provider name (after resource mapping) to runs-API action.
fn runs_api_action(provider: &str) -> Option<&'static str> {
    match provider {
        "claude" => Some("claude_reauth"),
        "codex" => Some("codex_reauth"),
        "kimi" => Some("kimi_reauth"),
        _ => None,
    }
}

fn runs_api_reauth(
    provider: &str,
    resource: &str,
    credential_expiry: i64,
    wait: Duration,
) -> Result<Option<bool>, String> {
    let url = runs_api_url()?;
    let token = reauth_token()
        .ok_or_else(|| "Weles runs API reauth requires WELES_API_TOKEN".to_string())?;
    let idempotency_key = reauth_idempotency_key(provider, resource, credential_expiry);
    runs_api_reauth_inner_with_idempotency(
        &url,
        &token,
        provider,
        resource,
        &idempotency_key,
        wait,
        reauth_timeout(),
    )
}

fn reauth_idempotency_key(
    provider: &str,
    resource: &str,
    credential_expiry: i64,
) -> String {
    format!("skarbiec-reauth:{provider}:{resource}:expires:{credential_expiry}")
}

#[cfg(test)]
fn runs_api_reauth_inner(
    url: &str,
    token: &str,
    provider: &str,
    resource: &str,
    wait: Duration,
    run_timeout: Duration,
) -> Result<Option<bool>, String> {
    let idempotency_key = reauth_idempotency_key(provider, resource, now_seconds());
    runs_api_reauth_inner_with_idempotency(
        url,
        token,
        provider,
        resource,
        &idempotency_key,
        wait,
        run_timeout,
    )
}

fn runs_api_reauth_inner_with_idempotency(
    url: &str,
    token: &str,
    provider: &str,
    resource: &str,
    idempotency_key: &str,
    wait: Duration,
    run_timeout: Duration,
) -> Result<Option<bool>, String> {
    let action = runs_api_action(provider)
        .ok_or_else(|| format!("no Weles reauth action for provider {provider}"))?;
    let agent = reauth_agent();
    let auth = format!("Bearer {token}");
    let started = Instant::now();
    // The run may take minutes server-side; the caller only waits `wait`. The
    // loop budget is the tighter of the run cap and the caller's patience.
    let budget = run_timeout.min(wait);
    let body = json!({
        "action": action,
        "params": {
            "source": "skarbiec",
            "reason": "credential_expired",
            "provider": provider,
            "resource": resource,
            "requested_at": chrono::Utc::now().to_rfc3339(),
        },
        "idempotency_key": idempotency_key,
        "priority": 100,
    });
    let response = agent
        .post(url)
        .set("Authorization", &auth)
        .set("Accept", "application/json")
        .timeout(budget)
        .send_json(body)
        .map_err(http_failure)?;
    let created: Value = response
        .into_json()
        .map_err(|_| "weles reauth create response is not JSON".to_string())?;
    let run = created.get("row").filter(|row| !row.is_null()).unwrap_or(&created);
    let run_id = run
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "weles reauth run id missing".to_string())?
        .to_string();
    let detail_url = run
        .get("detail_url")
        .and_then(Value::as_str)
        .filter(|url| !url.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{url}/{run_id}"));

    let mut last_body = run.clone();
    loop {
        match completed_reauth_result(&last_body)? {
            RunState::Refreshed => return Ok(Some(true)),
            RunState::Running => {}
        }
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            if wait < run_timeout {
                // The run continues server-side; debounce throttles retries and
                // a later redeem picks up the refreshed vault entry.
                return Ok(None);
            }
            return Err(format!(
                "Weles reauth run {run_id} did not complete within {}ms",
                run_timeout.as_millis()
            ));
        }
        std::thread::sleep(RUN_POLL_INTERVAL.min(remaining));
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            continue;
        }
        let response = agent
            .get(&detail_url)
            .set("Authorization", &auth)
            .set("Accept", "application/json")
            .timeout(remaining)
            .call()
            .map_err(http_failure)?;
        last_body = response
            .into_json()
            .map_err(|_| "weles reauth poll response is not JSON".to_string())?;
    }
}

struct StadoVaultConfig {
    base_url: String,
    token: String,
    uri: String,
}

impl Drop for StadoVaultConfig {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

fn stado_api_token() -> Result<String, String> {
    env_non_empty(&["STADO_API_TOKEN"]).ok_or_else(|| {
        "STADO_API_TOKEN is required; the trusted launcher must project \
         entitlements-rotator-object-api field token for consumer \
         entitlements-rotator-object-client"
            .to_string()
    })
}

fn is_loopback_http_url(value: &str) -> bool {
    ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|origin| {
            value == *origin
                || value.strip_prefix(origin).is_some_and(|suffix| {
                    if let Some(port_and_path) = suffix.strip_prefix(':') {
                        let port = port_and_path
                            .split('/')
                            .next()
                            .unwrap_or(port_and_path);
                        !port.is_empty() && port.chars().all(|character| character.is_ascii_digit())
                    } else {
                        suffix.starts_with('/')
                    }
                })
        })
}

/// Resolve the provider-neutral vault object. Remote persistence is
/// intentionally conditional: a local workstation can share the vault file
/// directly, while a hosted runtime opts in with an explicit stado:// locator.
fn stado_vault_config() -> Result<Option<StadoVaultConfig>, String> {
    let Some(uri) = env_non_empty(&["SKARBIEC_VAULT_URI"]) else {
        return Ok(None);
    };
    let key = uri
        .strip_prefix("stado://entitlements-rotator/")
        .ok_or_else(|| {
            "SKARBIEC_VAULT_URI must use stado://entitlements-rotator/<key>".to_string()
        })?;
    if key.is_empty() || key.starts_with('/') {
        return Err(
            "SKARBIEC_VAULT_URI must use stado://entitlements-rotator/<key>".to_string(),
        );
    }
    let base_url = env_non_empty(&["STADO_API_URL"])
        .ok_or_else(|| "STADO_API_URL is required for remote vault persistence".to_string())?;
    if !base_url.starts_with("https://") && !is_loopback_http_url(&base_url) {
        return Err("STADO_API_URL must use HTTPS or authenticated loopback HTTP".to_string());
    }
    let token = stado_api_token()?;
    Ok(Some(StadoVaultConfig {
        base_url: base_url.trim_end_matches('/').to_string(),
        token,
        uri,
    }))
}

fn stado_object_url(config: &StadoVaultConfig) -> String {
    format!(
        "{}/api/object?uri={}",
        config.base_url,
        url_encode(&config.uri)
    )
}

fn stado_request_failure(operation: &str, error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(code, _) => {
            format!("Stado vault {operation} returned HTTP {code}")
        }
        ureq::Error::Transport(_) => format!("Stado vault {operation} transport failure"),
    }
}

/// Re-pull the encrypted vault through Stado's provider-neutral object API.
/// No-op when no stado:// locator is configured. Provider credentials and
/// instance metadata never cross this boundary.
fn repull_vault_from_stado() -> Result<(), String> {
    let Some(config) = stado_vault_config()? else {
        return Ok(());
    };
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(STADO_PULL_TIMEOUT_MS))
        .redirects(u32::default())
        .build();
    let mut authorization = format!("Bearer {}", config.token);
    let response = agent
        .get(&stado_object_url(&config))
        .set("Authorization", &authorization)
        .call();
    authorization.zeroize();
    let response = response.map_err(|error| stado_request_failure("download", error))?;
    write_vault_atomic(&crate::core::vault_path(), &mut response.into_reader())
}

/// Persist the encrypted vault through its exact Stado object binding. The
/// scoped object bearer may come from an owner-only token file so Brama never
/// inherits it in its process environment.
pub(crate) fn push_vault_to_stado() -> Result<(), String> {
    let Some(config) = stado_vault_config()? else {
        return Ok(());
    };
    let body = fs::read(crate::core::vault_path())
        .map_err(|_| "vault read for push failed".to_string())?;
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(STADO_PUSH_TIMEOUT_MS))
        .redirects(u32::default())
        .build();
    let mut authorization = format!("Bearer {}", config.token);
    let response = agent
        .put(&stado_object_url(&config))
        .set("Authorization", &authorization)
        .set("Content-Type", "application/json")
        .send_bytes(&body);
    authorization.zeroize();
    response.map_err(|error| stado_request_failure("upload", error))?;
    Ok(())
}


/// Historical GCS transport fixture retained only so the pre-cutover embedded
/// tests compile. Production code cannot reach this function.
#[cfg(test)]
fn push_vault_to_gcs_inner(
    metadata_url: &str,
    storage_base: &str,
    bucket: &str,
    object: &str,
    vault_path: &Path,
) -> Result<(), String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(STADO_PUSH_TIMEOUT_MS))
        .redirects(u32::default())
        .build();
    let token: Value = agent
        .get(metadata_url)
        .set("Metadata-Flavor", "Google")
        .call()
        .map_err(|_| "gcs metadata token request failed".to_string())?
        .into_json()
        .map_err(|_| "gcs metadata token response is not JSON".to_string())?;
    let access_token = token
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "gcs metadata token missing".to_string())?;
    let url = format!(
        "{storage_base}/upload/storage/v1/b/{bucket}/o?uploadType=media&name={}",
        url_encode(object)
    );
    let body = fs::read(vault_path).map_err(|_| "vault read for push failed".to_string())?;
    agent
        .post(&url)
        .set("Authorization", &format!("Bearer {access_token}"))
        .set("Content-Type", "application/json")
        .send_bytes(&body)
        .map_err(|error| match error {
            ureq::Error::Status(code, _) => format!("gcs vault upload returned HTTP {code}"),
            ureq::Error::Transport(_) => "gcs vault upload transport failure".to_string(),
        })?;
    Ok(())
}

/// Python `urllib.parse.quote(safe="")`: keep unreserved bytes only.
fn url_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn write_vault_atomic(path: &Path, body: &mut impl Read) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "vault path has no parent".to_string())?;
    let mut suffix = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let temp = parent.join(format!(
        ".skarbiec-vault-stado-{}",
        suffix.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|_| "vault temp file failed".to_string())?;
        std::io::copy(body, &mut file).map_err(|_| "vault download write failed".to_string())?;
        file.sync_all().map_err(|_| "vault sync failed".to_string())?;
        fs::rename(&temp, path).map_err(|_| "vault replace failed".to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| "vault permissions failed".to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn reauth_attempts() -> &'static Mutex<HashMap<String, Instant>> {
    static ATTEMPTS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    ATTEMPTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// One reauth attempt per resource per debounce window, failures included.
fn mark_reauth_attempt(resource: &str) -> bool {
    let mut attempts = reauth_attempts()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    if let Some(last) = attempts.get(resource) {
        if now.duration_since(*last) < Duration::from_secs(REAUTH_DEBOUNCE_SECONDS) {
            return false;
        }
    }
    attempts.insert(resource.to_string(), now);
    true
}

/// Returns the fresh scalar secret when the current one is expired and Weles
/// confirms an out-of-band vault refresh within SKARBIEC_REAUTH_WAIT_MS. OAuth
/// refresh is owned exclusively by Brama's scoped provider runtime. Returns
/// None on failure, when the hook does not apply, or while a reauth triggered
/// here is still running server-side (debounce throttles retries and a later
/// redeem picks up the refreshed entry).
pub fn reauth_if_expired(resource: &str, secret: &str) -> Option<String> {
    let provider = weles_provider_for_resource(resource)?;
    let expiry = credential_expiry(secret)?;
    if now_seconds() + EXPIRY_MARGIN_SECONDS < expiry {
        return None;
    }
    if !mark_reauth_attempt(resource) {
        return None;
    }
    let wait = reauth_wait();
    match refresh_scalar(provider, resource, expiry, wait) {
        Ok(Some(fresh)) => Some(fresh),
        Ok(None) => {
            eprintln!("skarbiec reauth: {resource}: refresh still in progress");
            None
        }
        Err(error) => {
            eprintln!("skarbiec reauth: {resource}: {error}");
            None
        }
    }
}

fn refresh_scalar(
    provider: &str,
    resource: &str,
    credential_expiry: i64,
    wait: Duration,
) -> Result<Option<String>, String> {
    match trigger_weles_reauth(provider, resource, credential_expiry, wait)? {
        Some(true) => {}
        Some(false) => return Err("weles did not confirm a vault refresh".to_string()),
        None => return Ok(None),
    }
    repull_vault_from_stado()?;
    let vault = crate::core::vault::Vault::open(crate::core::vault_path())
        .map_err(|_| "vault reopen failed".to_string())?;
    let value = vault
        .get_item(resource)
        .map_err(|_| "vault re-read failed".to_string())?;
    let bytes = super::capability::extract_scalar_secret(value)
        .map_err(|_| "refreshed vault entry is not a scalar secret".to_string())?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| "refreshed vault entry is not UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_parser_detects_expired_nested_oauth() {
        let past_ms = (now_seconds() - 120) * 1_000;
        let secret = json!({
            "claudeAiOauth": {
                "accessToken": "redacted",
                "refreshToken": "redacted",
                "expiresAt": past_ms,
            }
        })
        .to_string();
        assert!(credential_expired(&secret));
    }

    #[test]
    fn expiry_parser_applies_margin() {
        let soon = now_seconds() + EXPIRY_MARGIN_SECONDS / 2;
        assert!(credential_expired(&json!({"expires_at": soon}).to_string()));
    }

    #[test]
    fn expiry_parser_accepts_fresh_epoch_seconds_and_millis() {
        let future = now_seconds() + 3_600;
        assert!(!credential_expired(
            &json!({"accessToken": "redacted", "refreshToken": "redacted", "expiresAt": future})
                .to_string()
        ));
        assert!(!credential_expired(&json!({"expiry": future * 1_000}).to_string()));
    }

    #[test]
    fn expiry_parser_reads_rfc3339_strings() {
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        assert!(credential_expired(&json!({"expires": past}).to_string()));
        assert!(!credential_expired(&json!({"expires": future}).to_string()));
    }

    #[test]
    fn expiry_parser_skips_missing_field_and_non_json() {
        assert!(!credential_expired(
            &json!({"accessToken": "redacted"}).to_string()
        ));
        assert!(!credential_expired("sk-plain-api-key"));
        assert!(!credential_expired("\"a json string\""));
        assert!(!credential_expired("[1, 2, 3]"));
    }

    #[test]
    fn weles_provider_mapping() {
        assert_eq!(
            weles_provider_for_resource("provider:claude-code:brama-sub-1"),
            Some("claude")
        );
        assert_eq!(
            weles_provider_for_resource("provider:codex:brama-sub-1"),
            Some("codex")
        );
        assert_eq!(
            weles_provider_for_resource("provider:kimi:brama-sub-1"),
            Some("kimi")
        );
        assert_eq!(weles_provider_for_resource("provider:openai:brama-sub-1"), None);
        assert_eq!(weles_provider_for_resource("provider:claude-code"), None);
        assert_eq!(weles_provider_for_resource("provider:claude-code:"), None);
        assert_eq!(
            weles_provider_for_resource("origin:https://example.test"),
            None
        );
    }

    #[test]
    fn runs_api_action_mapping() {
        assert_eq!(runs_api_action("claude"), Some("claude_reauth"));
        assert_eq!(runs_api_action("codex"), Some("codex_reauth"));
        assert_eq!(runs_api_action("kimi"), Some("kimi_reauth"));
        assert_eq!(runs_api_action("claude-code"), None);
        assert_eq!(runs_api_action("openai"), None);
    }

    #[test]
    fn response_claims_refresh_variants() {
        assert!(response_claims_refresh(&json!({"refreshed": true})));
        assert!(response_claims_refresh(&json!({"updated": true})));
        assert!(response_claims_refresh(
            &json!({"subscription": {"status": "active"}})
        ));
        assert!(!response_claims_refresh(&json!({"refreshed": false})));
        assert!(!response_claims_refresh(
            &json!({"subscription": {"status": "expired"}})
        ));
        assert!(!response_claims_refresh(&json!({})));
    }

    #[test]
    fn completed_reauth_result_waits_while_running() {
        for body in [
            json!({"status": "running"}),
            json!({"status": "queued"}),
            json!({"status": ""}),
            json!({}),
        ] {
            assert_eq!(
                completed_reauth_result(&body).unwrap(),
                RunState::Running,
                "{body} must keep polling"
            );
        }
    }

    #[test]
    fn completed_reauth_result_accepts_success_with_refresh_evidence() {
        for body in [
            json!({"status": "completed", "refreshed": true}),
            json!({"status": "succeeded", "updated": true}),
            json!({"status": "done", "subscription": {"status": "active"}}),
            json!({"status": "success", "result": {"note": "vault updated"}}),
        ] {
            assert_eq!(
                completed_reauth_result(&body).unwrap(),
                RunState::Refreshed,
                "{body} must complete the reauth"
            );
        }
    }

    #[test]
    fn completed_reauth_result_rejects_success_without_evidence() {
        assert!(completed_reauth_result(&json!({"status": "success"}))
            .unwrap_err()
            .contains("without result evidence"));
    }

    #[test]
    fn completed_reauth_result_rejects_failed_runs() {
        for status in ["failed", "error", "cancelled", "canceled"] {
            assert!(
                completed_reauth_result(&json!({"status": status}))
                    .unwrap_err()
                    .contains("run failed"),
                "{status} must fail the reauth"
            );
        }
    }

    #[test]
    fn completed_reauth_result_rejects_plaintext_credentials_anywhere() {
        for body in [
            json!({"status": "running", "token": "redacted"}),
            json!({"status": "completed", "refreshed": true, "apiKey": "redacted"}),
            json!({"status": "completed", "result": {"steps": [{"key": "redacted"}]}}),
            json!({"status": "completed", "result": [{"credential": "redacted"}]}),
        ] {
            assert!(
                completed_reauth_result(&body)
                    .unwrap_err()
                    .contains("forbidden plaintext credential"),
                "{body} must be rejected as plaintext-bearing"
            );
        }
    }

    /// Minimal loopback runs-API stub: canned JSON for the create POST and for
    /// every poll GET, one connection per request, closed after answering.
    fn spawn_runs_api_stub(post_body: &'static str, get_body: &'static str) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("stub server bind");
        let address = format!("http://{}", listener.local_addr().expect("stub server address"));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut reader =
                    BufReader::new(stream.try_clone().expect("stub stream clone"));
                let mut method = String::new();
                let mut content_length = 0usize;
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let header = line.trim_end().to_string();
                    if header.is_empty() {
                        break;
                    }
                    if method.is_empty() {
                        method = header
                            .split_whitespace()
                            .next()
                            .unwrap_or("")
                            .to_string();
                    }
                    if let Some((name, value)) = header.split_once(':') {
                        if name.trim().eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().unwrap_or(0);
                        }
                    }
                }
                if content_length > 0 {
                    let mut body = vec![0u8; content_length];
                    let _ = reader.read_exact(&mut body);
                }
                let payload = if method == "POST" { post_body } else { get_body };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        address
    }

    #[test]
    fn runs_api_wait_budget_returns_none_while_run_is_in_progress() {
        let url = spawn_runs_api_stub(
            r#"{"id":"run-1","status":"running"}"#,
            r#"{"id":"run-1","status":"running"}"#,
        );
        let started = Instant::now();
        let result = runs_api_reauth_inner(
            &url,
            "token",
            "claude",
            "provider:claude-code:sub",
            Duration::from_millis(300),
            Duration::from_secs(300),
        );
        assert_eq!(result, Ok(None));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "must resolve near the wait budget, not the run timeout"
        );
    }

    #[test]
    fn runs_api_sync_completion_succeeds_without_polling() {
        let url = spawn_runs_api_stub(
            r#"{"id":"run-2","status":"completed","refreshed":true}"#,
            r#"{"id":"run-2","status":"running"}"#,
        );
        let result = runs_api_reauth_inner(
            &url,
            "token",
            "claude",
            "provider:claude-code:sub",
            Duration::from_millis(300),
            Duration::from_secs(300),
        );
        assert_eq!(result, Ok(Some(true)));
    }

    #[test]
    fn runs_api_poll_completion_within_wait_budget_succeeds() {
        let url = spawn_runs_api_stub(
            r#"{"id":"run-3","status":"running"}"#,
            r#"{"id":"run-3","status":"completed","updated":true}"#,
        );
        let result = runs_api_reauth_inner(
            &url,
            "token",
            "codex",
            "provider:codex:sub",
            RUN_POLL_INTERVAL + Duration::from_millis(500),
            Duration::from_secs(300),
        );
        assert_eq!(result, Ok(Some(true)));
    }

    #[test]
    fn runs_api_run_timeout_errors_when_it_is_the_binding_cap() {
        let url = spawn_runs_api_stub(
            r#"{"id":"run-4","status":"running"}"#,
            r#"{"id":"run-4","status":"running"}"#,
        );
        let started = Instant::now();
        let result = runs_api_reauth_inner(
            &url,
            "token",
            "kimi",
            "provider:kimi:sub",
            Duration::from_secs(60),
            Duration::from_millis(300),
        );
        assert_eq!(
            result,
            Err("Weles reauth run run-4 did not complete within 300ms".to_string())
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    fn grant(access: &str, refresh: Option<&str>, expires_in: Option<u64>) -> RefreshGrant {
        RefreshGrant {
            access_token: access.to_string(),
            refresh_token: refresh.map(str::to_string),
            id_token: None,
            expires_in,
        }
    }

    #[test]
    fn direct_refresh_token_locations() {
        let claude = json!({"claudeAiOauth": {"refreshToken": "rt-claude"}});
        assert_eq!(direct_refresh_token(&claude, "claude"), Some("rt-claude"));
        let codex = json!({"tokens": {"refresh_token": "rt-codex"}});
        assert_eq!(direct_refresh_token(&codex, "codex"), Some("rt-codex"));
        let kimi = json!({"refresh_token": "rt-kimi"});
        assert_eq!(direct_refresh_token(&kimi, "kimi"), Some("rt-kimi"));
        assert_eq!(
            direct_refresh_token(&json!({"claudeAiOauth": {"accessToken": "x"}}), "claude"),
            None
        );
        assert_eq!(direct_refresh_token(&json!({"tokens": {}}), "codex"), None);
        assert_eq!(direct_refresh_token(&json!({}), "kimi"), None);
        assert_eq!(direct_refresh_token(&json!({"refresh_token": ""}), "kimi"), None);
    }

    #[test]
    fn patch_blob_claude_preserves_shape_and_millis_units() {
        let mut blob = json!({
            "claudeAiOauth": {
                "accessToken": "old-at",
                "refreshToken": "old-rt",
                "expiresAt": 1,
                "scopes": ["user:profile"],
                "subscriptionType": "pro",
            },
            "unrelated": {"keep": true},
        });
        assert!(patch_blob(
            &mut blob,
            "claude",
            &grant("new-at", Some("new-rt"), Some(3_600)),
            1_000
        ));
        let oauth = &blob["claudeAiOauth"];
        assert_eq!(oauth["accessToken"], "new-at");
        assert_eq!(oauth["refreshToken"], "new-rt");
        assert_eq!(oauth["expiresAt"], json!((1_000 + 3_600) * 1_000));
        assert_eq!(oauth["scopes"], json!(["user:profile"]));
        assert_eq!(oauth["subscriptionType"], "pro");
        assert_eq!(blob["unrelated"], json!({"keep": true}));
    }

    #[test]
    fn patch_blob_claude_keeps_refresh_token_and_expiry_when_not_returned() {
        let mut blob =
            json!({"claudeAiOauth": {"accessToken": "old", "refreshToken": "keep-rt", "expiresAt": 1}});
        assert!(patch_blob(&mut blob, "claude", &grant("new", None, None), 1_000));
        assert_eq!(blob["claudeAiOauth"]["refreshToken"], "keep-rt");
        assert_eq!(blob["claudeAiOauth"]["expiresAt"], json!(1));
    }

    #[test]
    fn patch_blob_codex_rotates_tokens_and_stamps_last_refresh() {
        let mut blob = json!({
            "tokens": {
                "access_token": "old-at",
                "refresh_token": "old-rt",
                "account_id": "acc-1",
                "id_token": "old-id",
            },
            "last_refresh": "2020-01-01T00:00:00+00:00",
        });
        assert!(patch_blob(
            &mut blob,
            "codex",
            &grant("new-at", Some("new-rt"), Some(3_600)),
            1_700_000_000
        ));
        let tokens = &blob["tokens"];
        assert_eq!(tokens["access_token"], "new-at");
        assert_eq!(tokens["refresh_token"], "new-rt");
        assert_eq!(tokens["id_token"], "old-id", "id_token preserved when not rotated");
        assert_eq!(tokens["account_id"], "acc-1");
        let stamp = blob["last_refresh"].as_str().expect("last_refresh string");
        assert_ne!(stamp, "2020-01-01T00:00:00+00:00");
        assert!(chrono::DateTime::parse_from_rfc3339(stamp).is_ok());
    }

    #[test]
    fn patch_blob_codex_rotates_id_token_and_omits_last_refresh_when_absent() {
        let mut blob =
            json!({"tokens": {"access_token": "old", "refresh_token": "r", "id_token": "old-id"}});
        let mut rotated = grant("new", None, None);
        rotated.id_token = Some("new-id".to_string());
        assert!(patch_blob(&mut blob, "codex", &rotated, 1_000));
        assert_eq!(blob["tokens"]["id_token"], "new-id");
        assert!(blob.get("last_refresh").is_none());
    }

    #[test]
    fn patch_blob_kimi_seconds_expiry_and_optional_rotation() {
        let mut blob = json!({
            "access_token": "old-at",
            "refresh_token": "old-rt",
            "expires_at": 1,
            "expires_in": 3_600,
            "scope": "s",
            "token_type": "bearer",
        });
        assert!(patch_blob(
            &mut blob,
            "kimi",
            &grant("new-at", None, Some(7_200)),
            1_000
        ));
        assert_eq!(blob["access_token"], "new-at");
        assert_eq!(blob["refresh_token"], "old-rt", "kimi refresh rotates only when returned");
        assert_eq!(blob["expires_at"], json!(1_000 + 7_200));
        assert_eq!(blob["scope"], "s");
        assert_eq!(blob["token_type"], "bearer");
        assert_eq!(blob["expires_in"], json!(3_600), "unrelated fields preserved");
    }

    #[test]
    fn patch_blob_rejects_wrong_shape() {
        assert!(!patch_blob(
            &mut json!({"accessToken": "x"}),
            "claude",
            &grant("a", None, None),
            1_000
        ));
        assert!(!patch_blob(
            &mut json!({"access_token": "x"}),
            "codex",
            &grant("a", None, None),
            1_000
        ));
        assert!(!patch_blob(
            &mut json!("a string"),
            "kimi",
            &grant("a", None, None),
            1_000
        ));
        assert!(!patch_blob(
            &mut json!({}),
            "openai",
            &grant("a", None, None),
            1_000
        ));
    }

    #[test]
    fn direct_refresh_skipped_without_refresh_token() {
        let config = direct_provider("claude").expect("claude direct config");
        let blob = json!({"claudeAiOauth": {"accessToken": "x", "expiresAt": 1}}).to_string();
        assert_eq!(
            try_direct_refresh_at(
                &config,
                Path::new("/nonexistent-vault"),
                "provider:claude-code:sub",
                "claude",
                &blob,
                Duration::from_millis(50),
            ),
            None,
            "no refreshToken must skip before any network or vault access"
        );
    }

    /// Loopback OAuth stub: every request gets the same status and JSON body.
    fn spawn_oauth_stub(status: u16, body: &'static str) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("stub server bind");
        let address = format!("http://{}", listener.local_addr().expect("stub server address"));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut reader = BufReader::new(stream.try_clone().expect("stub stream clone"));
                let mut content_length = 0usize;
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let header = line.trim_end().to_string();
                    if header.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.split_once(':') {
                        if name.trim().eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().unwrap_or(0);
                        }
                    }
                }
                if content_length > 0 {
                    let mut request_body = vec![0u8; content_length];
                    let _ = reader.read_exact(&mut request_body);
                }
                let response = format!(
                    "HTTP/1.1 {status} STUB\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        address
    }

    #[test]
    fn direct_refresh_invalid_grant_falls_through() {
        let url = spawn_oauth_stub(400, r#"{"error":"invalid_grant"}"#);
        let config = DirectProvider {
            token_endpoint: Box::leak(url.into_boxed_str()),
            client_id: "test-client",
            form: false,
        };
        let blob =
            json!({"claudeAiOauth": {"accessToken": "x", "refreshToken": "rt", "expiresAt": 1}})
                .to_string();
        assert_eq!(
            try_direct_refresh_at(
                &config,
                Path::new("/nonexistent-vault"),
                "provider:claude-code:sub",
                "claude",
                &blob,
                Duration::from_secs(5),
            ),
            None,
            "invalid_grant must fall through to the Weles path"
        );
    }

    struct Scratch(Option<std::path::PathBuf>);

    impl Scratch {
        fn new() -> Scratch {
            let mut random = [0u8; 4];
            rand::rngs::OsRng.fill_bytes(&mut random);
            // Short name: gpg-agent sockets must fit the ~104-byte sun_path limit.
            let root = std::env::temp_dir().join(format!(
                "skr-{}-{:08x}",
                std::process::id(),
                u32::from_ne_bytes(random),
            ));
            fs::create_dir(&root).expect("scratch directory");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("scratch permissions");
            Scratch(Some(root))
        }
        fn path(&self) -> &Path {
            self.0.as_ref().expect("scratch path")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            if let Some(root) = self.0.take() {
                let _ = fs::remove_dir_all(root);
            }
        }
    }

    fn gpg_available() -> bool {
        std::process::Command::new("gpg")
            .arg("--version")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    fn gpg(gnupg: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("gpg")
            .arg("--batch")
            .arg("--homedir")
            .arg(gnupg)
            .args(args)
            .output()
            .expect("gpg invocation");
        assert!(
            out.status.success(),
            "gpg {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn direct_refresh_success_writes_back_preserving_item_metadata() {
        if !gpg_available() {
            eprintln!("skipping write-back test: gpg unavailable");
            return;
        }
        let scratch = Scratch::new();
        let gnupg = scratch.path().join("gnupg");
        fs::create_dir(&gnupg).expect("gnupg directory");
        fs::set_permissions(&gnupg, fs::Permissions::from_mode(0o700)).expect("gnupg permissions");
        let prior_gnupghome = std::env::var("GNUPGHOME").ok();
        std::env::set_var("GNUPGHOME", &gnupg);
        gpg(
            &gnupg,
            &[
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "skarbiec reauth test <reauth@test.local>",
                "rsa2048",
                "encr",
                "never",
            ],
        );
        let keys = gpg(&gnupg, &["--with-colons", "--list-keys", "reauth@test.local"]);
        let fpr = keys
            .lines()
            .find(|line| line.starts_with("fpr:"))
            .and_then(|line| line.split(':').nth(9))
            .filter(|fpr| !fpr.is_empty())
            .expect("test key fingerprint")
            .to_string();

        let vault_path = scratch.path().join("vault.json");
        let resource = "provider:claude-code:sub-1";
        let blob = json!({
            "claudeAiOauth": {
                "accessToken": "old-at",
                "refreshToken": "old-rt",
                "expiresAt": 1,
                "scopes": ["user:profile"],
                "subscriptionType": "pro",
            }
        })
        .to_string();
        {
            let mut vault =
                crate::core::vault::Vault::create(vault_path.clone(), "owner", &fpr, "")
                    .expect("scratch vault");
            vault
                .set_item(
                    resource,
                    "credential",
                    &json!({"type": "credential", "value": blob}),
                    &["owner".to_string()],
                    &["credential-request".to_string(), "weles".to_string()],
                )
                .expect("seed credential");
        }
        let url = spawn_oauth_stub(
            200,
            r#"{"access_token":"fresh-at","refresh_token":"fresh-rt","expires_in":3600}"#,
        );
        let config = DirectProvider {
            token_endpoint: Box::leak(url.into_boxed_str()),
            client_id: "test-client",
            form: false,
        };
        let fresh = try_direct_refresh_at(
            &config,
            &vault_path,
            resource,
            "claude",
            &blob,
            Duration::from_secs(10),
        )
        .expect("direct refresh must succeed");
        let fresh_blob: Value = serde_json::from_str(&fresh).expect("fresh blob parses");
        let oauth = &fresh_blob["claudeAiOauth"];
        assert_eq!(oauth["accessToken"], "fresh-at");
        assert_eq!(oauth["refreshToken"], "fresh-rt");
        assert!(oauth["expiresAt"].as_i64().expect("expiry ms") > 1_000_000_000_000);
        assert_eq!(oauth["scopes"], json!(["user:profile"]));
        assert_eq!(oauth["subscriptionType"], "pro");

        let vault = crate::core::vault::Vault::open(vault_path).expect("reopen vault");
        let payload = vault.get_item(resource).expect("decrypt refreshed item");
        assert_eq!(payload["type"], "credential");
        assert_eq!(payload["value"].as_str().expect("scalar value"), fresh);
        let item = &vault.doc()["items"][resource];
        assert_eq!(item["type"], "credential");
        assert_eq!(item["recipients"], json!(["owner"]));
        assert_eq!(item["tags"], json!(["credential-request", "weles"]));

        match prior_gnupghome {
            Some(value) => std::env::set_var("GNUPGHOME", value),
            None => std::env::remove_var("GNUPGHOME"),
        }
    }

    /// Loopback GCS stub: GET answers a metadata-server token document, POST
    /// answers with `post_status`; every request (method, path, body) is
    /// recorded for assertions.
    fn spawn_capture_stub(
        post_status: u16,
    ) -> (
        String,
        std::sync::Arc<Mutex<Vec<(String, String, Vec<u8>)>>>,
    ) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("stub server bind");
        let address = format!("http://{}", listener.local_addr().expect("stub server address"));
        let captured = std::sync::Arc::new(Mutex::new(Vec::new()));
        let recorded = std::sync::Arc::clone(&captured);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut reader = BufReader::new(stream.try_clone().expect("stub stream clone"));
                let mut request_line = String::new();
                let mut content_length = 0usize;
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let header = line.trim_end().to_string();
                    if header.is_empty() {
                        break;
                    }
                    if request_line.is_empty() {
                        request_line = header.clone();
                    }
                    if let Some((name, value)) = header.split_once(':') {
                        if name.trim().eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().unwrap_or(0);
                        }
                    }
                }
                let mut body = vec![0u8; content_length];
                if content_length > 0 {
                    let _ = reader.read_exact(&mut body);
                }
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                recorded
                    .lock()
                    .expect("record request")
                    .push((method.clone(), path, body));
                let (status, payload) = if method == "POST" {
                    (post_status, "{}")
                } else {
                    (200, r#"{"access_token":"stub-token","expires_in":3600}"#)
                };
                let reason = if status == 200 { "OK" } else { "STUB" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (address, captured)
    }

    #[test]
    fn push_vault_to_gcs_uploads_current_file_bytes() {
        let (url, captured) = spawn_capture_stub(200);
        let scratch = Scratch::new();
        let vault_file = scratch.path().join("vault.json");
        fs::write(&vault_file, b"{\"items\":{}}").expect("vault bytes");
        push_vault_to_gcs_inner(&url, &url, "bucket-1", "obj dir/vault.json", &vault_file)
            .expect("push must succeed");
        let captured = captured.lock().expect("captured requests");
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].0, "GET", "metadata token request first");
        assert_eq!(captured[1].0, "POST");
        assert!(
            captured[1]
                .1
                .starts_with("/upload/storage/v1/b/bucket-1/o?uploadType=media&name="),
            "upload endpoint: {}",
            captured[1].1
        );
        assert!(
            captured[1].1.contains("obj%20dir%2Fvault.json"),
            "url-encoded object name: {}",
            captured[1].1
        );
        assert_eq!(captured[1].2, b"{\"items\":{}}", "file bytes land in the body");
    }

    #[test]
    fn push_vault_to_gcs_maps_upload_failure_to_err() {
        let (url, _captured) = spawn_capture_stub(500);
        let scratch = Scratch::new();
        let vault_file = scratch.path().join("vault.json");
        fs::write(&vault_file, b"{}").expect("vault bytes");
        let error =
            push_vault_to_gcs_inner(&url, &url, "bucket-1", "skarbiec.vault.json", &vault_file)
                .unwrap_err();
        assert!(error.contains("HTTP 500"), "{error}");
    }
}
