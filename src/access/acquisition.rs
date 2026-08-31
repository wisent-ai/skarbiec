// Short-lived, field-bound, single-use acquisition bearers. Registered
// workload identities may request an acquisition but can never read directly.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::access::tokens;
use crate::core::{crypto, schema, vault::Vault, vault_path};

struct StateLock {
    path: PathBuf,
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

fn private_file_mode() -> Result<u32> {
    u32::from_str_radix("600", "8".parse()?).context("private file mode")
}

fn private_dir_mode() -> Result<u32> {
    u32::from_str_radix("700", "8".parse()?).context("private directory mode")
}

fn unsafe_mode_bits() -> Result<u32> {
    u32::from_str_radix("077", "8".parse()?).context("unsafe mode bits")
}

fn effective_uid() -> Result<u32> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("read effective uid")?;
    if !output.status.success() {
        bail!("could not determine effective uid");
    }
    String::from_utf8(output.stdout)?
        .trim()
        .parse()
        .context("parse effective uid")
}

fn state_path() -> PathBuf {
    if let Ok(path) = std::env::var("SKARBIEC_ACQUISITION_FILE") {
        return PathBuf::from(path);
    }
    let vault = vault_path();
    let name = vault
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.acquisitions.json"))
        .unwrap_or_else(|| "skarbiec.vault.acquisitions.json".to_string());
    vault.with_file_name(name)
}

fn lock_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.lock"))
        .unwrap_or_else(|| "skarbiec.vault.acquisitions.lock".to_string());
    path.with_file_name(name)
}

fn acquire_lock(path: &Path) -> Result<StateLock> {
    let lock = lock_path(path);
    let attempts: usize = "500".parse()?;
    let pause = Duration::from_millis("10".parse()?);
    for _ in std::iter::repeat_n((), attempts) {
        match DirBuilder::new().mode(private_dir_mode()?).create(&lock) {
            Ok(()) => return Ok(StateLock { path: lock }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => thread::sleep(pause),
            Err(error) => return Err(error).context("create acquisition state lock"),
        }
    }
    bail!("acquisition state is locked")
}

fn validate_owned_regular(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.uid() != effective_uid()? {
        bail!("acquisition state must be an owner-controlled regular file");
    }
    if metadata.mode() & unsafe_mode_bits()? != u32::MIN {
        bail!("acquisition state permissions must not grant group or other access");
    }
    Ok(())
}

fn load_state(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(json!({"version": "v1", "tokens": {}, "proofs": {}}));
    }
    validate_owned_regular(path)?;
    let mut state: Value =
        serde_json::from_str(&fs::read_to_string(path)?).context("parse acquisition state")?;
    if state.get("version").and_then(Value::as_str) != Some("v1")
        || !state.get("tokens").is_some_and(Value::is_object)
    {
        bail!("invalid acquisition state document");
    }
    if state.get("proofs").is_none() {
        state["proofs"] = json!({});
    }
    if !state.get("proofs").is_some_and(Value::is_object) {
        bail!("invalid acquisition proof state");
    }
    Ok(state)
}

fn save_state(path: &Path, state: &Value) -> Result<()> {
    let parent = path.parent().context("acquisition state has no parent")?;
    fs::create_dir_all(parent)?;
    let suffix = format!("{}.{}", std::process::id(), now_epoch()?);
    let temp = path.with_extension(format!("tmp.{suffix}"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(private_file_mode()?)
        .open(&temp)
        .context("create acquisition state temporary file")?;
    let result = (|| -> Result<()> {
        file.write_all(serde_json::to_string_pretty(state)?.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(private_file_mode()?))?;
        fs::rename(&temp, path)?;
        let _ = File::open(parent).and_then(|directory| directory.sync_all());
        validate_owned_regular(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn now_epoch() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn ttl_seconds() -> Result<u64> {
    let ttl: u64 = std::env::var("SKARBIEC_ACQUISITION_TTL_SECONDS")
        .unwrap_or_else(|_| "30".to_string())
        .parse()
        .context("SKARBIEC_ACQUISITION_TTL_SECONDS must be an integer")?;
    let maximum: u64 = "300".parse()?;
    if ttl == u64::MIN || ttl > maximum {
        bail!("SKARBIEC_ACQUISITION_TTL_SECONDS must be between one and 300")
    }
    Ok(ttl)
}

fn exact_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_workload_id(value: &str) -> bool {
    let maximum: usize = "128".parse().unwrap_or_default();
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_nonce(value: &str) -> bool {
    let expected: usize = "43".parse().unwrap_or_default();
    value.len() == expected
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn decode_signature(value: &str) -> Option<Vec<u8>> {
    let expected: usize = "128".parse().ok()?;
    if value.len() != expected {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact("2".parse().ok()?)
        .map(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, "16".parse().ok()?).ok()
        })
        .collect()
}

fn workload_payload(
    consumer: &str,
    item: &str,
    field: &str,
    workload_id: &str,
    timestamp: u64,
    nonce: &str,
) -> Vec<u8> {
    format!(
        "SKARBIEC-WORKLOAD-ACQUISITION\0v1\0{consumer}\0{item}\0{field}\0{workload_id}\0{timestamp}\0{nonce}"
    )
    .into_bytes()
}

fn write_private_file(path: &Path, value: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(private_file_mode()?)
        .open(path)?;
    file.write_all(value)?;
    file.sync_all()?;
    Ok(())
}

/// Apple ships LibreSSL as `openssl`, but its `pkeyutl` cannot verify Ed25519
/// signatures. Prefer an installed OpenSSL 3 build and allow an explicit path.
fn openssl_bin() -> String {
    if let Ok(configured) = std::env::var("SKARBIEC_OPENSSL") {
        if !configured.is_empty() {
            return configured;
        }
    }
    for candidate in [
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
    ] {
        if Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "openssl".to_string()
}

fn verify_workload_proof(public_key: &str, payload: &[u8], signature: &str) -> Result<bool> {
    let Some(signature) = decode_signature(signature) else {
        return Ok(false);
    };
    let parent = state_path()
        .parent()
        .context("acquisition state has no parent")?
        .to_path_buf();
    fs::create_dir_all(&parent)?;
    let stem = crypto::sha256_hex(&crypto::random_token()?)?;
    let key_path = parent.join(format!(".skarbiec-proof-key-{stem}"));
    let signature_path = parent.join(format!(".skarbiec-proof-signature-{stem}"));
    let payload_path = parent.join(format!(".skarbiec-proof-payload-{stem}"));
    let result = (|| -> Result<bool> {
        write_private_file(&key_path, public_key.as_bytes())?;
        write_private_file(&signature_path, &signature)?;
        write_private_file(&payload_path, payload)?;
        let status = Command::new(openssl_bin())
            .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
            .arg(&key_path)
            .args(["-rawin", "-sigfile"])
            .arg(&signature_path)
            .arg("-in")
            .arg(&payload_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("verify workload proof with openssl")?;
        Ok(status.success())
    })();
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&signature_path);
    let _ = fs::remove_file(&payload_path);
    result
}

fn proof_window_seconds() -> Result<u64> {
    "30".parse().context("workload proof window")
}

fn validate_target(vault: &Vault, item: &str, field: &str) -> Result<()> {
    if !exact_name(item) || !exact_name(field) {
        bail!("item and field must be exact names without wildcards or separators");
    }
    let payload = vault.get_item(item)?;
    schema::field(&payload, field).context("acquisition field does not exist on item")?;
    Ok(())
}

fn purge_expired(state: &mut Value, now: u64) -> Result<()> {
    let tokens = state
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .context("acquisition tokens section")?;
    tokens.retain(|_, record| {
        record
            .get("expires_at")
            .and_then(Value::as_u64)
            .is_some_and(|expiry| expiry > now)
    });
    let proofs = state
        .get_mut("proofs")
        .and_then(Value::as_object_mut)
        .context("acquisition proofs section")?;
    proofs.retain(|_, expiry| expiry.as_u64().is_some_and(|value| value > now));
    Ok(())
}

pub struct IssuedAcquisition {
    pub token: String,
    pub expires_at: u64,
}

/// One redeemed acquisition: the bound field, and the item's declared provider
/// when it declares one.
pub struct AcquiredField {
    pub value: Value,
    pub provider: Option<String>,
}

/// The provider this credential belongs to, as the item itself declares it.
///
/// A reset flow has to know whether an account is Entra or consumer Microsoft
/// before it can drive anything, and the authoritative statement of that is
/// `context.provider`, sealed inside the ciphertext. Returning only the field
/// left the caller no way to ask, so the caller kept its own copy of the
/// mapping -- a hardcoded list of item names in another repository, which is a
/// second source of truth this response's shape created.
///
/// `provider` alone, deliberately, not the context object. The rest of what
/// context carries is either a personal identifier (`account_ref` is an
/// account address, and on a `login` item it restates the sealed `username`
/// field the caller holds no capability for), a customer identifier
/// (`tenant_ref`), lifecycle bookkeeping the caller already minted
/// (`request_id`, `operation`), or trajectory input nothing here needs
/// (`login_url`, `domains`, `session_label`, `login_method`, `name`,
/// `source_kind`). Two further members -- the sealed directory identity and
/// the provider receipt -- are owned end to end by the credential lifecycle.
/// A caller that genuinely needs the whole object asks for it with
/// `read:<item>#context`, which is the capability that exists for it.
///
/// Bounded with the same predicate capability routing applies to a declared
/// provider tag, so a value carrying a newline cannot break the line a caller
/// logs it on. A provider that is missing, non-text or unbounded yields
/// `None`, and `None` omits the key entirely: absence has to stay absence, not
/// an empty string a caller could read as a declaration.
fn declared_provider(payload: &Value) -> Option<String> {
    schema::field(payload, "context")
        .ok()?
        .get("provider")
        .and_then(Value::as_str)
        .filter(|provider| schema::exact_token(provider, schema::MAX_NAME_CHARS))
        .map(str::to_string)
}

pub fn issue(
    consumer: &str,
    item: &str,
    field: &str,
    workload_id: &str,
    timestamp: u64,
    nonce: &str,
    signature: &str,
) -> Result<Option<IssuedAcquisition>> {
    if !exact_name(consumer)
        || !exact_name(item)
        || !exact_name(field)
        || !valid_workload_id(workload_id)
        || !valid_nonce(nonce)
    {
        return Ok(None);
    }
    let vault = Vault::open(vault_path())?;
    let Some(public_key) = tokens::acquisition_workload_public_key(&vault, consumer, item, field)
    else {
        return Ok(None);
    };
    validate_target(&vault, item, field)?;
    let now = now_epoch()?;
    if now.abs_diff(timestamp) > proof_window_seconds()? {
        return Ok(None);
    }
    let payload = workload_payload(consumer, item, field, workload_id, timestamp, nonce);
    if !verify_workload_proof(&public_key, &payload, signature)? {
        return Ok(None);
    }

    let path = state_path();
    let _lock = acquire_lock(&path)?;
    let mut state = load_state(&path)?;
    purge_expired(&mut state, now)?;
    let proof_hash = crypto::sha256_hex(&format!("{workload_id}\0{nonce}"))?;
    let proofs = state
        .get_mut("proofs")
        .and_then(Value::as_object_mut)
        .context("acquisition proofs section")?;
    if proofs.contains_key(&proof_hash) {
        return Ok(None);
    }
    let replay_retention = proof_window_seconds()?
        .checked_mul("2".parse()?)
        .context("workload proof retention overflow")?;
    proofs.insert(
        proof_hash,
        json!(now
            .checked_add(replay_retention)
            .context("workload proof expiry overflow")?),
    );
    let expires_at = now
        .checked_add(ttl_seconds()?)
        .context("acquisition expiry overflow")?;
    let token = crypto::random_token()?;
    let hash = crypto::sha256_hex(&token)?;
    let tokens = state
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .context("acquisition tokens section")?;
    if tokens.contains_key(&hash) {
        bail!("acquisition token collision");
    }
    tokens.insert(
        hash,
        json!({
            "consumer": consumer,
            "item": item,
            "field": field,
            "expires_at": expires_at,
            "workload_id": workload_id,
        }),
    );
    save_state(&path, &state)?;
    Ok(Some(IssuedAcquisition { token, expires_at }))
}

pub fn consume(
    consumer: &str,
    presented: &str,
    item: &str,
    field: &str,
) -> Result<Option<AcquiredField>> {
    if !exact_name(consumer) || !exact_name(item) || !exact_name(field) || presented.is_empty() {
        return Ok(None);
    }
    let hash = crypto::sha256_hex(presented)?;
    let path = state_path();
    let _lock = acquire_lock(&path)?;
    let mut state = load_state(&path)?;
    let now = now_epoch()?;
    let record = state
        .get("tokens")
        .and_then(Value::as_object)
        .and_then(|tokens| tokens.get(&hash))
        .cloned();
    let Some(record) = record else {
        return Ok(None);
    };
    let expired = match record.get("expires_at").and_then(Value::as_u64) {
        Some(expiry) => expiry <= now,
        None => true,
    };
    if expired {
        state
            .get_mut("tokens")
            .and_then(Value::as_object_mut)
            .context("acquisition tokens section")?
            .remove(&hash);
        save_state(&path, &state)?;
        return Ok(None);
    }
    let bound = record.get("consumer").and_then(Value::as_str) == Some(consumer)
        && record.get("item").and_then(Value::as_str) == Some(item)
        && record.get("field").and_then(Value::as_str) == Some(field);
    if !bound {
        return Ok(None);
    }

    let vault = Vault::open(vault_path())?;
    // While an adopt is in flight the operator-supplied candidate is the only
    // value that proves anything, and only the adopt verification path may
    // read it. Outside that exact window a candidate is unreadable and the
    // single-use bearer is left unspent.
    //
    // The payload comes back from both branches so provenance costs no
    // decryption the redemption was not already paying: the current branch
    // opens the item anyway to take the field out of it. Only the staged
    // branch, the adopt window, adds one open, and it adds it with `ok()` --
    // provenance must never turn a redemption that has already proved its
    // capability into a failure.
    let (value, payload) = match crate::credential::managed_read(&vault, item, field, consumer)? {
        crate::credential::ManagedRead::Staged(candidate) => (candidate, vault.get_item(item).ok()),
        crate::credential::ManagedRead::Refused => return Ok(None),
        crate::credential::ManagedRead::Current => {
            let payload = vault.get_item(item)?;
            let value = schema::field(&payload, field)
                .cloned()
                .context("acquisition field no longer exists on item")?;
            (value, Some(payload))
        }
    };
    let provider = payload.as_ref().and_then(declared_provider);
    state
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .context("acquisition tokens section")?
        .remove(&hash);
    save_state(&path, &state)?;
    Ok(Some(AcquiredField { value, provider }))
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "acquisition-request" => {
            let consumer = positionals.first().context(
                "usage: acquisition-request <consumer> <item> <field> --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX",
            )?;
            let item = positionals.get("1".parse::<usize>()?).context(
                "usage: acquisition-request <consumer> <item> <field> --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX",
            )?;
            let field = positionals.get("2".parse::<usize>()?).context(
                "usage: acquisition-request <consumer> <item> <field> --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX",
            )?;
            let workload_id = flags.get("workload-id").context("--workload-id required")?;
            let timestamp = flags
                .get("workload-timestamp")
                .context("--workload-timestamp required")?
                .parse()
                .context("--workload-timestamp must be an epoch integer")?;
            let nonce = flags
                .get("workload-nonce")
                .context("--workload-nonce required")?;
            let signature = flags
                .get("workload-signature")
                .context("--workload-signature required")?;
            let Some(issued) = issue(
                consumer,
                item,
                field,
                workload_id,
                timestamp,
                nonce,
                signature,
            )?
            else {
                return Ok(Some(json!({"ok": false, "error": "unauthorized"})));
            };
            crate::runtime::audit::append_sync(
                "acquisition-issued",
                &json!({
                    "consumer": consumer,
                    "item": item,
                    "field": field,
                    "workload_id": workload_id,
                    "expires_at": issued.expires_at,
                }),
            )?;
            Ok(Some(json!({
                "ok": true,
                "consumer": consumer,
                "item": item,
                "field": field,
                "expires_at": issued.expires_at,
                "token": issued.token,
            })))
        }
        "acquisition-read" => {
            let consumer = positionals
                .first()
                .context("usage: acquisition-read <consumer> <item> <field> --token ACQUISITION")?;
            let item = positionals
                .get("1".parse::<usize>()?)
                .context("usage: acquisition-read <consumer> <item> <field> --token ACQUISITION")?;
            let field = positionals
                .get("2".parse::<usize>()?)
                .context("usage: acquisition-read <consumer> <item> <field> --token ACQUISITION")?;
            let presented = flags.get("token").context("--token required")?;
            let Some(acquired) = consume(consumer, presented, item, field)? else {
                return Ok(Some(json!({"ok": false, "error": "unauthorized"})));
            };
            crate::runtime::audit::append_sync(
                "acquisition-consumed",
                &json!({"consumer": consumer, "item": item, "field": field}),
            )?;
            let mut answer = json!({
                "ok": true,
                "consumer": consumer,
                "item": item,
                "field": field,
                "value": acquired.value,
            });
            if let Some(provider) = acquired.provider {
                answer["provider"] = json!(provider);
            }
            Ok(Some(answer))
        }
        _ => Ok(None),
    }
}
