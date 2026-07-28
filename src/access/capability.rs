//! Least-privilege capability broker and normative `skarbiec.redeem.v1` wire.
//! Persistent records contain opaque identifiers and vault references, never plaintext.

use anyhow::{bail, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::core::vault::is_apple_challenge_resource;
use zeroize::{Zeroize, Zeroizing};

use super::reauth;

const POLICY_DOMAIN: &[u8] = b"SKARBIEC-AGENT-POLICY\0v1\0";
const REGISTRY_DOMAIN: &[u8] = b"SKARBIEC-WORKLOAD-REGISTRY\0v1\0";
const PROOF_DOMAIN: &[u8] = b"SKARBIEC-WORKLOAD-PROOF\0v1\0";
const WIRE_VERSION: &str = "skarbiec.redeem.v1";
const MAX_REQUEST: u64 = 16_384;
const APPLE_CHALLENGE_NAMESPACE: &str = "challenge:apple/*";
const APPLE_CHALLENGE_PURPOSE: &str = "weles.apple.2fa";
const APPLE_CHALLENGE_TYPE: &str = "apple-challenge";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    purpose: String,
    resource: String,
    target: String,
    max_ttl_seconds: u64,
    max_uses: u64,
    delegation_depth: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    not_before: u64,
    expires_at: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Agent {
    roles: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    grant_id: String,
    not_before: u64,
    expires_at: u64,
    revoked: bool,
    rules: Vec<Rule>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rate {
    issue_per_minute: u64,
    redeem_failures_per_minute: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: String,
    sequence: u64,
    environment: String,
    worm_command_sha256: String,
    roles: BTreeMap<String, Vec<Rule>>,
    agents: BTreeMap<String, Agent>,
    agent_grants: BTreeMap<String, Vec<Grant>>,
    environment_allow: Vec<Rule>,
    deny: Vec<Rule>,
    leases: BTreeMap<String, Lease>,
    rate: Rate,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustRoot {
    version: String,
    policy_key: String,
    workload_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Workload {
    target: String,
    uid: u32,
    gid: u32,
    executable_path: String,
    executable_sha256: String,
    proof_key: String,
    agent_ids: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: String,
    sequence: u64,
    workloads: BTreeMap<String, Workload>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerRequest {
    version: String,
    capability_id: String,
    nonce: String,
    workload_id: String,
    proof: String,
    authorization_id: Option<String>,
    operation: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointRecord {
    version: String,
    segment: u64,
    event_hash: String,
    receipt: String,
}

pub struct Broker {
    policy: Policy,
    registry: Registry,
    conn: Connection,
    socket: PathBuf,
    socket_gid: u32,
    worm_command: PathBuf,
    checkpoint: PathBuf,
}

enum BrokerOutcome {
    Secret(Vec<u8>),
    Pending,
    Cancelled,
}

fn env_path(name: &str) -> Result<PathBuf> {
    let raw =
        std::env::var(name).with_context(|| format!("required configuration {name} is missing"))?;
    let path = PathBuf::from(raw.trim());
    if raw.trim().is_empty() || !path.is_absolute() {
        bail!("{name} must be a nonblank absolute path");
    }
    Ok(path)
}
fn owner_only(path: &Path, regular: bool) -> Result<()> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if meta.file_type().is_symlink() || (regular && !meta.is_file()) {
        bail!("unsafe configured path: {}", path.display());
    }
    if meta.uid() != unsafe { libc::geteuid() } || meta.permissions().mode() & 0o077 != 0 {
        bail!("{} must be owner-only", path.display());
    }
    Ok(())
}
fn secure_parent(path: &Path) -> Result<()> {
    let parent = path.parent().context("configured path has no parent")?;
    owner_only(parent, false)
}
fn socket_group() -> Result<u32> {
    let configured = std::env::var("SKARBIEC_CAP_SOCKET_GID")
        .context("required configuration SKARBIEC_CAP_SOCKET_GID is missing")?;
    let gid: u32 = configured
        .parse()
        .context("SKARBIEC_CAP_SOCKET_GID must be a numeric GID")?;
    let name = CString::new("skarbiec-capability-clients")?;
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if group.is_null() {
        bail!("required socket group skarbiec-capability-clients does not exist");
    }
    let expected = unsafe { (*group).gr_gid };
    if gid != expected || gid != unsafe { libc::getegid() } {
        bail!("SKARBIEC_CAP_SOCKET_GID must match the broker effective capability-clients group");
    }
    Ok(gid)
}
fn secure_socket_parent(path: &Path, gid: u32) -> Result<()> {
    let parent = path.parent().context("socket path has no parent")?;
    let meta =
        fs::symlink_metadata(parent).with_context(|| format!("inspect {}", parent.display()))?;
    if meta.file_type().is_symlink()
        || !meta.is_dir()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.gid() != gid
        || meta.permissions().mode() & 0o7777 != 0o750
    {
        bail!("socket parent must be owner-controlled 0750 with the capability-clients group");
    }
    Ok(())
}
fn set_socket_access(path: &Path, gid: u32) -> Result<()> {
    let raw = CString::new(path.as_os_str().as_encoded_bytes())?;
    if unsafe { libc::chown(raw.as_ptr(), libc::geteuid(), gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("set capability socket ownership");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_socket()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.gid() != gid
        || meta.permissions().mode() & 0o7777 != 0o660
    {
        bail!("capability socket ownership or permissions are unsafe");
    }
    Ok(())
}
fn read_owner_file(path: &Path) -> Result<Vec<u8>> {
    owner_only(path, true)?;
    fs::read(path).with_context(|| format!("read {}", path.display()))
}
fn strict_json<T: for<'a> Deserialize<'a>>(bytes: &[u8], what: &str) -> Result<T> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut de).with_context(|| format!("invalid {what}"))?;
    de.end()
        .with_context(|| format!("trailing data in {what}"))?;
    Ok(value)
}
fn key(raw: &str) -> Result<VerifyingKey> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .context("invalid public key encoding")?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&array).context("invalid Ed25519 public key")
}
fn verify_signed<T: for<'a> Deserialize<'a>>(
    doc: &Path,
    sig: &Path,
    domain: &[u8],
    key: &VerifyingKey,
    what: &str,
) -> Result<T> {
    let bytes = read_owner_file(doc)?;
    let sig_text = String::from_utf8(read_owner_file(sig)?).context("signature is not UTF-8")?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_text.trim())
        .context("invalid signature encoding")?;
    let signature = Signature::from_slice(&sig_bytes).context("invalid Ed25519 signature")?;
    let mut signed = Vec::with_capacity(domain.len() + bytes.len());
    signed.extend_from_slice(domain);
    signed.extend_from_slice(&bytes);
    key.verify(&signed, &signature)
        .with_context(|| format!("invalid {what} signature"))?;
    strict_json(&bytes, what)
}
fn valid_atom(value: &str) -> bool {
    !value.trim().is_empty() && value == value.trim() && value != "*" && !value.contains('\0')
}
fn valid_authorization_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}
fn append_proof_context(
    proof: &mut Vec<u8>,
    operation: Option<&str>,
    authorization_id: Option<&str>,
) {
    if let Some(operation) = operation {
        proof.push(0);
        proof.extend_from_slice(operation.as_bytes());
        proof.push(0);
        if let Some(authorization_id) = authorization_id {
            proof.extend_from_slice(authorization_id.as_bytes());
        }
    }
}
fn concrete_prefixed(resource: &str, prefixes: &[&str]) -> bool {
    !resource.contains('*')
        && prefixes.iter().any(|prefix| {
            resource
                .strip_prefix(prefix)
                .is_some_and(|suffix| valid_atom(suffix))
        })
}
fn is_apple_challenge_rule(rule: &Rule) -> bool {
    rule.target == "weles"
        && rule.purpose == APPLE_CHALLENGE_PURPOSE
        && is_apple_challenge_resource(&rule.resource)
}
fn is_apple_namespace_bound(rule: &Rule) -> bool {
    rule.target == "weles"
        && rule.purpose == APPLE_CHALLENGE_PURPOSE
        && rule.resource == APPLE_CHALLENGE_NAMESPACE
}
fn validate_rule_with_namespace(
    rule: &Rule,
    allow_deny_star: bool,
    allow_apple_namespace: bool,
) -> Result<()> {
    let policy_apple_namespace = allow_apple_namespace && is_apple_namespace_bound(rule);
    for value in [&rule.purpose, &rule.resource, &rule.target] {
        if !valid_atom(value)
            && !(allow_deny_star && value == &"*")
            && !(policy_apple_namespace && value.as_str() == rule.resource.as_str())
        {
            bail!("policy contains blank or broad compatibility scope");
        }
    }
    if rule.max_ttl_seconds == 0 || rule.max_uses == 0 {
        bail!("policy bounds must be positive");
    }
    if allow_deny_star && (rule.purpose == "*" || rule.resource == "*" || rule.target == "*") {
        return Ok(());
    }
    let canonical = match (rule.target.as_str(), rule.purpose.as_str()) {
        ("weles", "weles.browser.fill") => concrete_prefixed(&rule.resource, &["origin:"]),
        ("weles", "weles.captcha.solve" | "weles.sms.verify") => {
            concrete_prefixed(&rule.resource, &["provider:"])
        }
        ("weles", "weles.apple.2fa") => {
            (is_apple_challenge_resource(&rule.resource)
                || (allow_apple_namespace && rule.resource == APPLE_CHALLENGE_NAMESPACE))
                && rule.max_uses == 1
        }
        ("weles", "weles.proxy.authenticate") => concrete_prefixed(&rule.resource, &["proxy:"]),
        ("weles", "weles.brama.sign") => concrete_prefixed(&rule.resource, &["brama:", "agent:"]),
        ("most-service", "most.api.wisent-backend.authenticate") => {
            rule.resource == "credential:most/wisent-backend-most-api"
        }
        ("most-service", "most.api.most-agent.authenticate") => {
            rule.resource == "credential:most/most-agent-api"
        }
        ("most-service", "most.database.connect") => rule.resource == "credential:most/database",
        ("most-service", "most.attachment.sign") => {
            rule.resource == "credential:most/attachment-signing"
        }
        ("most-service", "most.remote-worker.authenticate") => {
            rule.resource == "credential:most/remote-worker"
        }
        ("brama", "brama.provider.authenticate") => {
            concrete_prefixed(&rule.resource, &["provider:"])
        }
        ("brama", "brama.supabase.connect") => concrete_prefixed(&rule.resource, &["supabase:"]),
        ("brama", "brama.request.sign") => concrete_prefixed(&rule.resource, &["agent:"]),
        ("singularity-bootstrap", "singularity.brama.bootstrap") => {
            concrete_prefixed(&rule.resource, &["brama:"])
        }
        ("singularity-bootstrap", "singularity.most.bootstrap") => {
            concrete_prefixed(&rule.resource, &["most:"])
        }
        _ => false,
    };
    if !canonical {
        bail!("capability is outside the closed purpose/resource/target taxonomy");
    }
    Ok(())
}
fn validate_rule(rule: &Rule, allow_deny_star: bool) -> Result<()> {
    validate_rule_with_namespace(rule, allow_deny_star, false)
}
fn within(request: &Rule, bound: &Rule) -> bool {
    request.purpose == bound.purpose
        && (request.resource == bound.resource
            || (is_apple_challenge_rule(request) && is_apple_namespace_bound(bound)))
        && request.target == bound.target
        && request.max_ttl_seconds <= bound.max_ttl_seconds
        && request.max_uses <= bound.max_uses
        && request.delegation_depth <= bound.delegation_depth
}
fn denied(request: &Rule, deny: &Rule) -> bool {
    (deny.purpose == "*" || deny.purpose == request.purpose)
        && (deny.resource == "*" || deny.resource == request.resource)
        && (deny.target == "*" || deny.target == request.target)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock before epoch")?
        .as_secs())
}
fn hash_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn strictly_newer(current: u64, candidate: u64) -> Result<bool> {
    if candidate < current {
        bail!("signed configuration sequence rollback");
    }
    Ok(candidate > current)
}
fn anomaly_threshold_crossed(count: u64, limit: u64) -> bool {
    count == limit.saturating_add(1)
}
pub(crate) fn zeroize_json_strings(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json_strings),
        Value::Object(values) => values.values_mut().for_each(zeroize_json_strings),
        _ => {}
    }
}
pub(crate) fn extract_scalar_secret(mut item: Value) -> Result<Vec<u8>> {
    let result = match &mut item {
        Value::String(value) if !value.is_empty() => Ok(std::mem::take(value).into_bytes()),
        Value::Object(fields) => {
            let exact = fields.len() == 2
                && fields
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(valid_atom)
                && fields
                    .get("value")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty());
            if !exact {
                Err(anyhow::anyhow!(
                    "vault resource is not a dedicated scalar secret"
                ))
            } else {
                match fields.get_mut("value") {
                    Some(Value::String(value)) => Ok(std::mem::take(value).into_bytes()),
                    _ => Err(anyhow::anyhow!("vault scalar secret is invalid")),
                }
            }
        }
        _ => Err(anyhow::anyhow!(
            "vault resource is not a nonempty scalar secret"
        )),
    };
    zeroize_json_strings(&mut item);
    result
}
fn extract_apple_challenge(mut item: Value) -> Result<Vec<u8>> {
    let result = match &mut item {
        Value::Object(fields)
            if fields.len() == 2
                && fields.get("type").and_then(Value::as_str) == Some(APPLE_CHALLENGE_TYPE) =>
        {
            match fields.get_mut("value") {
                Some(Value::String(value))
                    if value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit()) =>
                {
                    Ok(std::mem::take(value).into_bytes())
                }
                _ => Err(anyhow::anyhow!(
                    "Apple challenge is not exactly six ASCII digits"
                )),
            }
        }
        _ => Err(anyhow::anyhow!(
            "Apple challenge is not a dedicated scalar secret"
        )),
    };
    zeroize_json_strings(&mut item);
    result
}
fn ensure_distinct_trust_roots(policy: &VerifyingKey, workload: &VerifyingKey) -> Result<()> {
    if policy == workload {
        bail!("policy and workload registry trust roots must be distinct");
    }
    Ok(())
}
fn workload_allows_agent(workload: &Workload, agent: &str) -> bool {
    workload.agent_ids.iter().any(|allowed| allowed == agent)
}
fn read_redeem_request(stream: &UnixStream) -> Result<BrokerRequest> {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .context("set redemption framing timeout")?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(MAX_REQUEST + 1)
        .read_until(b'\n', &mut bytes)?;
    if bytes.len() as u64 > MAX_REQUEST || !bytes.ends_with(b"\n") {
        bail!("invalid request framing");
    }
    let mut trailing = [0u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => bail!("trailing bytes after redemption request"),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            bail!("redemption request must end with EOF")
        }
        Err(error) => return Err(error).context("verify redemption request EOF"),
    }
    bytes.pop();
    strict_json(&bytes, "redeem request")
}
#[cfg(target_os = "linux")]
fn ensure_redemption_supported() -> Result<()> {
    Ok(())
}
#[cfg(target_os = "macos")]
fn ensure_redemption_supported() -> Result<()> {
    bail!("capability redemption is unsupported on macOS because peer executable identity cannot be guaranteed")
}

impl Broker {
    pub fn open() -> Result<Self> {
        let trust_path = env_path("SKARBIEC_CAP_TRUST_ROOT")?;
        let trust: TrustRoot = strict_json(&read_owner_file(&trust_path)?, "trust root")?;
        if trust.version != "v1" {
            bail!("unsupported trust root version");
        }
        let policy_key = key(&trust.policy_key)?;
        let workload_key = key(&trust.workload_key)?;
        ensure_distinct_trust_roots(&policy_key, &workload_key)?;
        let policy = verify_signed(
            &env_path("SKARBIEC_CAP_POLICY")?,
            &env_path("SKARBIEC_CAP_POLICY_SIG")?,
            POLICY_DOMAIN,
            &policy_key,
            "policy",
        )?;
        let registry = verify_signed(
            &env_path("SKARBIEC_WORKLOAD_REGISTRY")?,
            &env_path("SKARBIEC_WORKLOAD_REGISTRY_SIG")?,
            REGISTRY_DOMAIN,
            &workload_key,
            "workload registry",
        )?;
        let policy: Policy = policy;
        let registry: Registry = registry;
        if policy.version != "v1"
            || registry.version != "v1"
            || policy.sequence == 0
            || registry.sequence == 0
            || !valid_atom(&policy.environment)
        {
            bail!("unsupported or incomplete signed configuration");
        }
        if policy.roles.is_empty() || policy.environment_allow.is_empty() {
            bail!("signed policy has no bounded authorization surface");
        }
        for (role, rules) in &policy.roles {
            if !valid_atom(role) || rules.is_empty() {
                bail!("invalid role definition");
            }
            for rule in rules {
                validate_rule_with_namespace(rule, false, true)?;
            }
        }
        for (agent, identity) in &policy.agents {
            if !valid_atom(agent) || identity.roles.is_empty() {
                bail!("invalid agent identity");
            }
            let mut roles = BTreeSet::new();
            for role in &identity.roles {
                if !roles.insert(role) || !policy.roles.contains_key(role) {
                    bail!("agent references an invalid or duplicate role");
                }
            }
        }
        for (agent, lease) in &policy.leases {
            if !policy.agents.contains_key(agent) || lease.not_before >= lease.expires_at {
                bail!("invalid agent lease");
            }
        }
        for (agent, grants) in &policy.agent_grants {
            let identity = policy
                .agents
                .get(agent)
                .context("grant references unknown agent")?;
            let mut grant_ids = BTreeSet::new();
            for grant in grants {
                if !valid_atom(&grant.grant_id)
                    || !grant_ids.insert(&grant.grant_id)
                    || grant.not_before >= grant.expires_at
                    || grant.rules.is_empty()
                {
                    bail!("invalid signed grant rotation window");
                }
                for rule in &grant.rules {
                    validate_rule_with_namespace(rule, false, true)?;
                    let role_subset = identity
                        .roles
                        .iter()
                        .filter_map(|r| policy.roles.get(r))
                        .flatten()
                        .any(|bound| within(rule, bound));
                    let env_subset = policy
                        .environment_allow
                        .iter()
                        .any(|bound| within(rule, bound));
                    if !role_subset || !env_subset {
                        bail!("agent grant expands role or environment policy");
                    }
                }
            }
        }
        for rule in &policy.environment_allow {
            validate_rule_with_namespace(rule, false, true)?;
        }
        for rule in &policy.deny {
            validate_rule(rule, true)?;
        }
        if policy.rate.issue_per_minute == 0 || policy.rate.redeem_failures_per_minute == 0 {
            bail!("rate limits must be positive");
        }
        for (workload_id, workload) in &registry.workloads {
            if !valid_atom(workload_id)
                || !["weles", "most-service", "brama", "singularity-bootstrap"]
                    .contains(&workload.target.as_str())
                || !Path::new(&workload.executable_path).is_absolute()
                || !valid_atom(&workload.executable_path)
            {
                bail!("invalid workload identity or target");
            }
            if workload.executable_sha256.len() != 64
                || !workload
                    .executable_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                bail!("invalid workload executable digest");
            }
            key(&workload.proof_key)?;
            if workload.agent_ids.is_empty() {
                bail!("workload agent allowlist must be nonempty");
            }
            let mut agent_ids = BTreeSet::new();
            for agent_id in &workload.agent_ids {
                if !valid_atom(agent_id)
                    || !agent_ids.insert(agent_id)
                    || !policy.agents.contains_key(agent_id)
                {
                    bail!("workload agent allowlist is invalid");
                }
            }
        }
        let state = env_path("SKARBIEC_CAP_STATE")?;
        secure_parent(&state)?;
        if state.exists() {
            owner_only(&state, true)?;
        }
        let mut conn = Connection::open(&state).context("open capability state")?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o600))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS capabilities(id_hash TEXT PRIMARY KEY,agent TEXT NOT NULL,purpose TEXT NOT NULL,resource TEXT NOT NULL,target TEXT NOT NULL,authorization_id TEXT,issued_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,max_uses INTEGER NOT NULL,uses INTEGER NOT NULL DEFAULT 0,depth INTEGER NOT NULL,parent_hash TEXT,cancelled INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS replay(id_hash TEXT NOT NULL,nonce_hash TEXT NOT NULL,PRIMARY KEY(id_hash,nonce_hash));
          CREATE TABLE IF NOT EXISTS counters(kind TEXT NOT NULL,subject TEXT NOT NULL,window INTEGER NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(kind,subject,window));
          CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,segment INTEGER NOT NULL,at INTEGER NOT NULL,kind TEXT NOT NULL,subject_hash TEXT NOT NULL,prev_hash TEXT NOT NULL,event_hash TEXT NOT NULL,receipt TEXT NOT NULL);")?;
        let has_authorization_id = {
            let mut statement = conn.prepare("PRAGMA table_info(capabilities)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            let mut found = false;
            for column in columns {
                if column? == "authorization_id" {
                    found = true;
                }
            }
            found
        };
        if !has_authorization_id {
            conn.execute(
                "ALTER TABLE capabilities ADD COLUMN authorization_id TEXT",
                [],
            )?;
        }
        {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let stored: Option<u64> = tx
                .query_row("SELECT v FROM meta WHERE k='policy_sequence'", [], |r| {
                    r.get(0)
                })
                .optional()?;
            if stored.is_some_and(|v| policy.sequence < v) {
                bail!("policy sequence rollback");
            }
            let reg_stored: Option<u64> = tx
                .query_row("SELECT v FROM meta WHERE k='registry_sequence'", [], |r| {
                    r.get(0)
                })
                .optional()?;
            if reg_stored.is_some_and(|v| registry.sequence < v) {
                bail!("registry sequence rollback");
            }
            tx.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES('policy_sequence',?1)",
                [policy.sequence],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES('registry_sequence',?1)",
                [registry.sequence],
            )?;
            tx.commit()?;
        }
        let socket = env_path("SKARBIEC_CAP_SOCKET")?;
        let socket_gid = socket_group()?;
        secure_socket_parent(&socket, socket_gid)?;
        let worm_dir = env_path("SKARBIEC_WORM_RECEIPT_DIR")?;
        owner_only(&worm_dir, false)?;
        let worm_command = env_path("SKARBIEC_WORM_RECEIPT_COMMAND")?;
        owner_only(&worm_command, true)?;
        if policy.worm_command_sha256.len() != 64
            || hash_file(&worm_command)? != policy.worm_command_sha256.to_ascii_lowercase()
        {
            bail!("WORM command digest mismatch");
        }
        let checkpoint = env_path("SKARBIEC_WORM_CHECKPOINT")?;
        secure_parent(&checkpoint)?;
        if checkpoint.exists() {
            owner_only(&checkpoint, true)?;
        }
        verify_checkpoint(&conn, &checkpoint)?;
        let broker = Self {
            policy,
            registry,
            conn,
            socket,
            socket_gid,
            worm_command,
            checkpoint,
        };
        broker.purge_inactive_apple_challenges()?;
        Ok(broker)
    }

    fn purge_inactive_apple_challenges(&self) -> Result<()> {
        let at = now()?;
        let resources = {
            let mut statement = self.conn.prepare(
                "SELECT DISTINCT resource FROM capabilities \
                 WHERE purpose=?1 AND (cancelled=1 OR expires_at<=?2 OR uses>=max_uses)",
            )?;
            let rows = statement.query_map(params![APPLE_CHALLENGE_PURPOSE, at], |row| {
                row.get::<_, String>(0)
            })?;
            rows.collect::<rusqlite::Result<BTreeSet<String>>>()?
        };
        if resources.is_empty() {
            return Ok(());
        }
        let mut vault = crate::core::vault::Vault::open(crate::core::vault_path())?;
        for resource in resources {
            if is_apple_challenge_resource(&resource) {
                vault.purge_apple_challenge(&resource)?;
            }
        }
        Ok(())
    }

    fn authorized(&self, agent: &str, requested: &Rule) -> Result<()> {
        if !valid_atom(agent) {
            bail!("invalid agent");
        }
        let lease = self.policy.leases.get(agent).context("no active lease")?;
        let at = now()?;
        if at < lease.not_before
            || at >= lease.expires_at
            || requested.max_ttl_seconds > lease.expires_at.saturating_sub(at)
        {
            bail!("lease inactive");
        }
        if self.policy.deny.iter().any(|d| denied(requested, d)) {
            bail!("denied by policy");
        }
        if !self
            .policy
            .environment_allow
            .iter()
            .any(|r| within(requested, r))
        {
            bail!("outside environment constraints");
        }
        let identity = self.policy.agents.get(agent).context("unknown agent")?;
        let role_ok = identity
            .roles
            .iter()
            .filter_map(|r| self.policy.roles.get(r))
            .flatten()
            .any(|r| within(requested, r));
        let grant_ok = self.policy.agent_grants.get(agent).is_some_and(|grants| {
            grants.iter().any(|grant| {
                !grant.revoked
                    && at >= grant.not_before
                    && at < grant.expires_at
                    && requested.max_ttl_seconds <= grant.expires_at.saturating_sub(at)
                    && grant.rules.iter().any(|r| within(requested, r))
            })
        });
        if !(role_ok && grant_ok) {
            bail!("no active bounded grant");
        }
        Ok(())
    }

    fn rate_available(&self, kind: &str, subject: &str, limit: u64) -> Result<bool> {
        let window = now()? / 60;
        let subject = hash_hex(subject.as_bytes());
        let count: Option<u64> = self
            .conn
            .query_row(
                "SELECT count FROM counters WHERE kind=?1 AND subject=?2 AND window=?3",
                params![kind, subject, window],
                |r| r.get(0),
            )
            .optional()?;
        Ok(count.unwrap_or(0) < limit)
    }

    fn rate(&self, kind: &str, subject: &str, limit: u64) -> Result<()> {
        let window = now()? / 60;
        let subject = hash_hex(subject.as_bytes());
        let count: u64 = self.conn.query_row(
            "INSERT INTO counters(kind,subject,window,count) VALUES(?1,?2,?3,1) ON CONFLICT(kind,subject,window) DO UPDATE SET count=count+1 RETURNING count",
            params![kind, subject, window], |r| r.get(0),
        )?;
        if count > limit {
            bail!("rate limit exceeded");
        }
        Ok(())
    }

    fn record_redeem_failure(&mut self, subject: &str) -> Result<bool> {
        let window = now()? / 60;
        let subject_hash = hash_hex(subject.as_bytes());
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: u64 = tx.query_row(
            "INSERT INTO counters(kind,subject,window,count) VALUES('redeem_failure',?1,?2,1) ON CONFLICT(kind,subject,window) DO UPDATE SET count=count+1 RETURNING count",
            params![subject_hash, window], |r| r.get(0),
        )?;
        let exceeded = count > self.policy.rate.redeem_failures_per_minute;
        if anomaly_threshold_crossed(count, self.policy.rate.redeem_failures_per_minute) {
            checkpoint_tx(
                &self.worm_command,
                &self.checkpoint,
                tx,
                "anomaly",
                &subject_hash,
            )?;
        } else {
            tx.commit()?;
        }
        Ok(exceeded)
    }

    fn reload_signed_configuration(&mut self) -> Result<()> {
        let fresh = Self::open()?;
        let policy_newer = strictly_newer(self.policy.sequence, fresh.policy.sequence)?;
        let registry_newer = strictly_newer(self.registry.sequence, fresh.registry.sequence)?;
        if policy_newer {
            self.policy = fresh.policy;
        }
        if registry_newer {
            self.registry = fresh.registry;
        }
        Ok(())
    }

    fn issue_rule(
        &mut self,
        agent: &str,
        requested: &Rule,
        parent_hash: Option<&str>,
        authorization_id: Option<&str>,
    ) -> Result<String> {
        validate_rule(requested, false)?;
        if let Some(value) = authorization_id {
            if !valid_authorization_id(value)
                || requested.max_uses != 1
                || requested.delegation_depth != 0
            {
                bail!("authorization-bound capabilities require a canonical id, max_uses=1, and no delegation");
            }
        }
        let apple_sensitive = requested.purpose == APPLE_CHALLENGE_PURPOSE
            || requested.resource == "origin:https://idmsa.apple.com/email"
            || requested.resource == "origin:https://idmsa.apple.com/password";
        if apple_sensitive && authorization_id.is_none() {
            bail!("Apple authentication capabilities require authorization binding");
        }
        self.authorized(agent, requested)?;
        self.rate("issue", agent, self.policy.rate.issue_per_minute)?;
        let mut opaque = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut opaque);
        let id = opaque
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let issued = now()?;
        let expires = issued
            .checked_add(requested.max_ttl_seconds)
            .context("TTL overflow")?;
        let id_hash = hash_hex(id.as_bytes());
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO capabilities(id_hash,agent,purpose,resource,target,authorization_id,issued_at,expires_at,max_uses,depth,parent_hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", params![id_hash,agent,requested.purpose,requested.resource,requested.target,authorization_id,issued,expires,requested.max_uses,requested.delegation_depth,parent_hash])?;
        checkpoint_tx(&self.worm_command, &self.checkpoint, tx, "issue", &id_hash)?;
        Ok(id)
    }

    pub fn issue(
        &mut self,
        agent: &str,
        purpose: &str,
        resource: &str,
        target: &str,
        ttl: u64,
        max_uses: u64,
        depth: u32,
    ) -> Result<String> {
        self.issue_bound(agent, purpose, resource, target, ttl, max_uses, depth, None)
    }

    pub fn issue_bound(
        &mut self,
        agent: &str,
        purpose: &str,
        resource: &str,
        target: &str,
        ttl: u64,
        max_uses: u64,
        depth: u32,
        authorization_id: Option<&str>,
    ) -> Result<String> {
        let requested = Rule {
            purpose: purpose.into(),
            resource: resource.into(),
            target: target.into(),
            max_ttl_seconds: ttl,
            max_uses,
            delegation_depth: depth,
        };
        self.issue_rule(agent, &requested, None, authorization_id)
    }

    pub fn status(&self, id: &str) -> Result<Value> {
        let h = hash_hex(id.as_bytes());
        let row: Option<(u64, u64, u64, bool)> = self
            .conn
            .query_row(
                "SELECT expires_at,max_uses,uses,cancelled FROM capabilities WHERE id_hash=?1",
                [h],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, u64>(3)? != 0)),
            )
            .optional()?;
        Ok(match row {
            Some((expires, max, uses, cancelled)) => {
                json!({"known":true,"active":!cancelled && now()? < expires && uses < max,"expires_at":expires,"remaining_uses":max.saturating_sub(uses)})
            }
            None => json!({"known":false}),
        })
    }

    pub fn cancel(&mut self, agent: &str, id: &str) -> Result<()> {
        self.cancel_bound(agent, id, None)
    }

    pub fn cancel_bound(
        &mut self,
        agent: &str,
        id: &str,
        authorization_id: Option<&str>,
    ) -> Result<()> {
        if authorization_id.is_some_and(|value| !valid_authorization_id(value)) {
            bail!("invalid authorization id");
        }
        let h = hash_hex(id.as_bytes());
        let row: (String, i64) = self.conn.query_row(
            "SELECT resource,cancelled FROM capabilities WHERE id_hash=?1 AND agent=?2 AND authorization_id IS ?3",
            params![h,agent,authorization_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).context("capability not found")?;
        if row.1 == 0 {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = tx.execute(
                "UPDATE capabilities SET cancelled=1 WHERE id_hash=?1 AND agent=?2 AND authorization_id IS ?3 AND cancelled=0",
                params![h,agent,authorization_id],
            )?;
            if changed != 1 {
                bail!("capability cancellation lost race");
            }
            checkpoint_tx(&self.worm_command, &self.checkpoint, tx, "cancel", &h)?;
        }
        if is_apple_challenge_resource(&row.0) {
            let mut vault = crate::core::vault::Vault::open(crate::core::vault_path())?;
            vault.purge_apple_challenge(&row.0)?;
        }
        Ok(())
    }

    pub fn delegate(
        &mut self,
        agent: &str,
        parent: &str,
        target: &str,
        ttl: u64,
        max_uses: u64,
    ) -> Result<String> {
        let h = hash_hex(parent.as_bytes());
        let row: (String,String,String,u64,u64,u64,u32,bool,Option<String>) = self.conn.query_row(
            "SELECT purpose,resource,target,expires_at,max_uses,uses,depth,cancelled,authorization_id FROM capabilities WHERE id_hash=?1 AND agent=?2",
            params![h,agent],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get::<_,u64>(7)? != 0,r.get(8)?)),
        ).context("parent capability not found")?;
        let at = now()?;
        if row.7
            || row.8.is_some()
            || row.6 == 0
            || at >= row.3
            || ttl > row.3.saturating_sub(at)
            || max_uses > row.4.saturating_sub(row.5)
            || target != row.2
        {
            bail!("delegation expansion denied");
        }
        let requested = Rule {
            purpose: row.0,
            resource: row.1,
            target: target.into(),
            max_ttl_seconds: ttl,
            max_uses,
            delegation_depth: row.6 - 1,
        };
        validate_rule(&requested, false)?;
        self.authorized(agent, &requested)?;
        self.rate("issue", agent, self.policy.rate.issue_per_minute)?;

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: (u64,u64,u64,u32,bool,String) = tx.query_row("SELECT expires_at,max_uses,uses,depth,cancelled,target FROM capabilities WHERE id_hash=?1 AND agent=?2", params![h,agent], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get::<_,u64>(4)? != 0,r.get(5)?))).context("parent capability not found")?;
        let at = now()?;
        if current.4
            || current.3 == 0
            || at >= current.0
            || ttl > current.0.saturating_sub(at)
            || max_uses > current.1.saturating_sub(current.2)
            || target != current.5
        {
            bail!("delegation expansion denied");
        }
        tx.execute(
            "UPDATE capabilities SET uses=uses+?1 WHERE id_hash=?2",
            params![max_uses, h],
        )?;
        let mut opaque = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut opaque);
        let id = opaque
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let id_hash = hash_hex(id.as_bytes());
        let expires = at.checked_add(ttl).context("TTL overflow")?;
        tx.execute("INSERT INTO capabilities(id_hash,agent,purpose,resource,target,issued_at,expires_at,max_uses,depth,parent_hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", params![id_hash,agent,requested.purpose,requested.resource,requested.target,at,expires,max_uses,requested.delegation_depth,h])?;
        checkpoint_tx(&self.worm_command, &self.checkpoint, tx, "issue", &id_hash)?;
        Ok(id)
    }

    pub fn available(
        &self,
        agent: &str,
        purpose: &str,
        resource: &str,
        target: &str,
        ttl: u64,
        max_uses: u64,
    ) -> bool {
        let r = Rule {
            purpose: purpose.into(),
            resource: resource.into(),
            target: target.into(),
            max_ttl_seconds: ttl,
            max_uses,
            delegation_depth: 0,
        };
        validate_rule(&r, false)
            .and_then(|_| self.authorized(agent, &r))
            .is_ok()
            && self
                .rate_available("issue", agent, self.policy.rate.issue_per_minute)
                .unwrap_or(false)
    }

    pub fn health(&self) -> Result<Value> {
        let active: u64 = self.conn.query_row("SELECT count(*) FROM capabilities WHERE cancelled=0 AND expires_at>?1 AND uses<max_uses", [now()?], |r| r.get(0))?;
        let anomalies: u64 = self.conn.query_row(
            "SELECT count(*) FROM events WHERE kind='anomaly'",
            [],
            |r| r.get(0),
        )?;
        Ok(
            json!({"ok":true,"service":"skarbiec-capability-broker","wire":WIRE_VERSION,"policy_sequence":self.policy.sequence,"registry_sequence":self.registry.sequence,"active_capabilities":active,"anomaly_count":anomalies}),
        )
    }

    pub fn serve(mut self) -> Result<()> {
        ensure_redemption_supported()?;
        if self.socket.exists() {
            bail!("socket path already exists; refusing to unlink it");
        }
        let listener = UnixListener::bind(&self.socket)?;
        set_socket_access(&self.socket, self.socket_gid)?;
        for incoming in listener.incoming() {
            if let Ok(mut stream) = incoming {
                if self.reload_signed_configuration().is_err() {
                    stream.write_all(
                        b"{\"version\":\"skarbiec.redeem.v1\",\"status\":\"denied\"}\n",
                    )?;
                    stream.flush()?;
                    continue;
                }
                let _ = self.handle_stream(stream);
            }
        }
        Ok(())
    }
    fn handle_stream(&mut self, mut stream: UnixStream) -> Result<()> {
        let subject = peer_identity(&stream).map(|(uid, gid, _)| format!("{uid}:{gid}"));
        let attempt = match subject.as_ref() {
            Ok(subject)
                if self
                    .rate_available(
                        "redeem_failure",
                        subject,
                        self.policy.rate.redeem_failures_per_minute,
                    )
                    .unwrap_or(false) =>
            {
                self.redeem(&stream)
            }
            _ => Err(anyhow::anyhow!(
                "peer redemption is rate limited or unauthenticated"
            )),
        };
        match attempt {
            Ok(BrokerOutcome::Secret(mut secret)) => {
                let written = (|| -> Result<()> {
                    let control = json!({"version": WIRE_VERSION, "status": "ok", "secret_len": secret.len()});
                    stream.write_all(serde_json::to_string(&control)?.as_bytes())?;
                    stream.write_all(b"\n")?;
                    stream.write_all(&secret)?;
                    Ok(())
                })();
                secret.zeroize();
                written?;
            }
            Ok(BrokerOutcome::Pending) => {
                stream
                    .write_all(b"{\"version\":\"skarbiec.redeem.v1\",\"status\":\"pending\"}\n")?;
            }
            Ok(BrokerOutcome::Cancelled) => {
                stream.write_all(
                    b"{\"version\":\"skarbiec.redeem.v1\",\"status\":\"ok\",\"secret_len\":0}\n",
                )?;
            }
            Err(error) => {
                eprintln!("capability redemption denied: {error:#}");
                let recorded =
                    self.record_redeem_failure(subject.as_deref().unwrap_or("unknown-peer"));
                stream
                    .write_all(b"{\"version\":\"skarbiec.redeem.v1\",\"status\":\"denied\"}\n")?;
                stream.flush()?;
                recorded?;
                return Ok(());
            }
        }
        stream.flush()?;
        Ok(())
    }

    fn redeem(&mut self, stream: &UnixStream) -> Result<BrokerOutcome> {
        ensure_redemption_supported()?;
        let (uid, gid, pid) = peer_identity(stream)?;
        let request = read_redeem_request(stream)?;
        if request.version != WIRE_VERSION
            || request.capability_id.len() != 64
            || !request
                .capability_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !valid_atom(&request.nonce)
            || request.nonce.len() > 128
            || !valid_atom(&request.workload_id)
            || request
                .operation
                .as_deref()
                .is_some_and(|operation| !matches!(operation, "redeem" | "cancel"))
            || (request.authorization_id.is_some() && request.operation.is_none())
            || request
                .authorization_id
                .as_deref()
                .is_some_and(|value| !valid_authorization_id(value))
            || request.proof.len() != 86
        {
            bail!("invalid request");
        }
        let workload = self
            .registry
            .workloads
            .get(&request.workload_id)
            .context("unknown workload")?;
        let (peer_path, peer_start) = peer_process(pid)?;
        if uid != workload.uid
            || gid != workload.gid
            || peer_path != PathBuf::from(&workload.executable_path)
            || hash_file(&peer_path)? != workload.executable_sha256.to_ascii_lowercase()
        {
            bail!("peer mismatch");
        }
        let mut proof = Vec::new();
        proof.extend_from_slice(PROOF_DOMAIN);
        proof.extend_from_slice(request.capability_id.as_bytes());
        proof.push(0);
        proof.extend_from_slice(request.nonce.as_bytes());
        proof.push(0);
        proof.extend_from_slice(request.workload_id.as_bytes());
        append_proof_context(
            &mut proof,
            request.operation.as_deref(),
            request.authorization_id.as_deref(),
        );
        let proof_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&request.proof)
            .context("invalid proof encoding")?;
        let signature = Signature::from_slice(&proof_bytes).context("invalid proof")?;
        key(&workload.proof_key)?
            .verify(&proof, &signature)
            .context("invalid workload proof")?;
        let (confirmed_path, confirmed_start) = peer_process(pid)?;
        if confirmed_path != peer_path || confirmed_start != peer_start {
            bail!("peer process changed during authentication");
        }

        self.purge_inactive_apple_challenges()?;

        let operation = request.operation.as_deref().unwrap_or("redeem");
        let h = hash_hex(request.capability_id.as_bytes());
        let nonce = hash_hex(request.nonce.as_bytes());
        let row: (String, String, String, u64, u64, u64, bool, Option<String>) = self.conn.query_row(
            "SELECT agent,purpose,resource,expires_at,max_uses,uses,cancelled,authorization_id FROM capabilities WHERE id_hash=?1 AND target=?2",
            params![h, workload.target],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get::<_, u64>(6)? != 0, r.get(7)?)),
        ).context("capability unavailable")?;
        if !workload_allows_agent(workload, &row.0)
            || (row.6 && operation != "cancel")
            || row.7.as_deref() != request.authorization_id.as_deref()
        {
            bail!("capability inactive, authorization mismatch, or workload is not authorized for its agent");
        }
        if operation == "redeem" && (now()? >= row.3 || row.5 >= row.4) {
            bail!("capability expired or exhausted");
        }

        if operation == "cancel" {
            if !row.6 {
                commit_workload_cancellation(
                    &mut self.conn,
                    &self.worm_command,
                    &self.checkpoint,
                    &h,
                    &nonce,
                    &workload.target,
                    &row.0,
                    request.authorization_id.as_deref(),
                )?;
            }
            if is_apple_challenge_resource(&row.2) {
                let mut vault = crate::core::vault::Vault::open(crate::core::vault_path())?;
                vault.purge_apple_challenge(&row.2)?;
            }
            return Ok(BrokerOutcome::Cancelled);
        }

        let apple_challenge =
            row.1 == APPLE_CHALLENGE_PURPOSE && is_apple_challenge_resource(&row.2);
        if apple_challenge && row.4 != 1 {
            bail!("Apple challenge capability is not one-use");
        }
        let mut vault = crate::core::vault::Vault::open(crate::core::vault_path())?;
        let value = if apple_challenge {
            match vault.take_apple_challenge(&row.2)? {
                Some(value) => value,
                None => return Ok(BrokerOutcome::Pending),
            }
        } else {
            vault.get_item(&row.2)?
        };
        let mut secret = if apple_challenge {
            extract_apple_challenge(value)?
        } else {
            extract_scalar_secret(value)?
        };
        if !apple_challenge {
            // Reauth does network I/O (OAuth refresh, Weles, Stado). It must not
            // run while this process holds the vault flock, or every other
            // vault open (e.g. the router's `list` for subscription discovery)
            // blocks for the whole reauth duration.
            drop(vault);
            if let Ok(text) = std::str::from_utf8(&secret) {
                if let Some(fresh) = reauth::reauth_if_expired(&row.2, text) {
                    secret = fresh.into_bytes();
                }
            }
        }
        if secret.len() > 1_048_576 {
            secret.zeroize();
            bail!("socket secret exceeds configured wire limit");
        }
        if let Err(error) = commit_redemption(
            &mut self.conn,
            &self.worm_command,
            &self.checkpoint,
            &h,
            &nonce,
            &workload.target,
            &row.0,
            &row.2,
            request.authorization_id.as_deref(),
        ) {
            secret.zeroize();
            return Err(error);
        }
        Ok(BrokerOutcome::Secret(secret))
    }
}
fn commit_redemption(
    conn: &mut Connection,
    worm_command: &Path,
    checkpoint: &Path,
    id_hash: &str,
    nonce_hash: &str,
    target: &str,
    expected_agent: &str,
    expected_resource: &str,
    expected_authorization_id: Option<&str>,
) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current: (String, String, u64, u64, u64, bool, Option<String>) = tx.query_row(
        "SELECT agent,resource,expires_at,max_uses,uses,cancelled,authorization_id FROM capabilities WHERE id_hash=?1 AND target=?2",
        params![id_hash, target],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get::<_, u64>(5)? != 0, r.get(6)?)),
    ).context("capability unavailable")?;
    if current.0 != expected_agent
        || current.1 != expected_resource
        || current.6.as_deref() != expected_authorization_id
        || current.5
        || now()? >= current.2
        || current.4 >= current.3
    {
        bail!("capability inactive, authorization mismatch, or workload is not authorized for its agent");
    }
    tx.execute(
        "INSERT INTO replay(id_hash,nonce_hash) VALUES(?1,?2)",
        params![id_hash, nonce_hash],
    )
    .context("replay")?;
    let changed = tx.execute(
        "UPDATE capabilities SET uses=uses+1 WHERE id_hash=?1 AND cancelled=0 AND uses<max_uses",
        [id_hash],
    )?;
    if changed != 1 {
        bail!("capability inactive");
    }
    checkpoint_tx(worm_command, checkpoint, tx, "redeem", id_hash)
}

fn commit_workload_cancellation(
    conn: &mut Connection,
    worm_command: &Path,
    checkpoint: &Path,
    id_hash: &str,
    nonce_hash: &str,
    target: &str,
    expected_agent: &str,
    expected_authorization_id: Option<&str>,
) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current: (String, bool, Option<String>) = tx.query_row(
        "SELECT agent,cancelled,authorization_id FROM capabilities WHERE id_hash=?1 AND target=?2",
        params![id_hash, target],
        |r| Ok((r.get(0)?, r.get::<_, u64>(1)? != 0, r.get(2)?)),
    ).context("capability unavailable")?;
    if current.0 != expected_agent || current.1 || current.2.as_deref() != expected_authorization_id
    {
        bail!("capability cancellation authorization mismatch");
    }
    tx.execute(
        "INSERT INTO replay(id_hash,nonce_hash) VALUES(?1,?2)",
        params![id_hash, nonce_hash],
    )
    .context("replay")?;
    let changed = tx.execute(
        "UPDATE capabilities SET cancelled=1 WHERE id_hash=?1 AND cancelled=0",
        [id_hash],
    )?;
    if changed != 1 {
        bail!("capability cancellation lost race");
    }
    checkpoint_tx(worm_command, checkpoint, tx, "cancel", id_hash)
}

fn put_apple_challenge(
    flags: &std::collections::HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    if !flags.is_empty() || positionals.len() != 1 || !is_apple_challenge_resource(&positionals[0])
    {
        bail!("usage: apple-challenge-put <challenge:apple/canonical-lowercase-UUID>");
    }
    let resource = &positionals[0];
    let mut input = Zeroizing::new(Vec::new());
    std::io::stdin().take(7).read_to_end(&mut input)?;
    if input.len() != 6 || !input.iter().all(u8::is_ascii_digit) {
        bail!("Apple challenge stdin must contain exactly six ASCII digits and EOF");
    }
    let code = std::str::from_utf8(&input).context("Apple challenge is not ASCII")?;
    let mut secret = json!({"type": APPLE_CHALLENGE_TYPE, "value": code});
    let stored = (|| -> Result<()> {
        let mut vault = crate::core::vault::Vault::open(crate::core::vault_path())?;
        vault.put_apple_challenge(resource, &secret)
    })();
    zeroize_json_strings(&mut secret);
    stored?;
    Ok(json!({"status":"stored", "resource":resource}))
}

fn required<'a>(
    flags: &'a std::collections::HashMap<String, String>,
    name: &str,
) -> Result<&'a str> {
    flags
        .get(name)
        .map(String::as_str)
        .filter(|v| valid_atom(v))
        .with_context(|| format!("--{name} is required"))
}

pub fn dispatch(
    command: &str,
    flags: &std::collections::HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "apple-challenge-put" => Ok(Some(put_apple_challenge(flags, positionals)?)),
        "capability-serve" => {
            Broker::open()?.serve()?;
            Ok(Some(json!({"ok": true})))
        }
        "capability-issue" => {
            if !positionals.is_empty() {
                bail!("capability-issue accepts named arguments only");
            }
            let mut broker = Broker::open()?;
            let id = broker.issue_bound(
                required(flags, "agent")?,
                required(flags, "purpose")?,
                required(flags, "resource")?,
                required(flags, "target")?,
                required(flags, "ttl")?.parse()?,
                required(flags, "max-uses")?.parse()?,
                flags
                    .get("delegation-depth")
                    .map(String::as_str)
                    .unwrap_or("0")
                    .parse()?,
                flags.get("authorization-id").map(String::as_str),
            )?;
            Ok(Some(json!({"status":"issued","capability_id":id})))
        }
        "capability-status" => {
            if !flags.is_empty() || positionals.len() != 1 {
                bail!("usage: capability-status <capability-id>");
            }
            Ok(Some(Broker::open()?.status(&positionals[0])?))
        }
        "capability-cancel" => {
            if !positionals.is_empty() {
                bail!("capability-cancel accepts named arguments only");
            }
            let mut broker = Broker::open()?;
            if let Some(authorization_id) = flags.get("authorization-id").map(String::as_str) {
                broker.cancel_bound(
                    required(flags, "agent")?,
                    required(flags, "capability-id")?,
                    Some(authorization_id),
                )?;
            } else {
                broker.cancel(required(flags, "agent")?, required(flags, "capability-id")?)?;
            }
            Ok(Some(json!({"status":"cancelled"})))
        }
        "capability-delegate" => {
            if !positionals.is_empty() {
                bail!("capability-delegate accepts named arguments only");
            }
            let mut broker = Broker::open()?;
            let id = broker.delegate(
                required(flags, "agent")?,
                required(flags, "capability-id")?,
                required(flags, "target")?,
                required(flags, "ttl")?.parse()?,
                required(flags, "max-uses")?.parse()?,
            )?;
            Ok(Some(json!({"status":"issued","capability_id":id})))
        }
        _ => Ok(None),
    }
}

fn verify_checkpoint(conn: &Connection, checkpoint: &Path) -> Result<()> {
    let mut statement = conn.prepare(
        "SELECT segment,at,kind,subject_hash,prev_hash,event_hash,receipt FROM events ORDER BY seq",
    )?;
    let mut rows = statement.query([])?;
    let mut previous = String::new();
    let mut latest: Option<(u64, String, String)> = None;
    while let Some(row) = rows.next()? {
        let segment: u64 = row.get(0)?;
        let at: u64 = row.get(1)?;
        let kind: String = row.get(2)?;
        let subject_hash: String = row.get(3)?;
        let stored_previous: String = row.get(4)?;
        let event_hash: String = row.get(5)?;
        let receipt: String = row.get(6)?;
        if !matches!(kind.as_str(), "issue" | "redeem" | "cancel" | "anomaly")
            || segment != at / 86_400
            || stored_previous != previous
            || receipt.is_empty()
            || receipt.len() > 4096
        {
            bail!("capability audit chain is invalid");
        }
        let material = format!("v1|{stored_previous}|{at}|{kind}|{subject_hash}");
        if hash_hex(material.as_bytes()) != event_hash {
            bail!("capability audit chain hash mismatch");
        }
        previous = event_hash.clone();
        latest = Some((segment, event_hash, receipt));
    }
    match latest {
        None if checkpoint.exists() => bail!("checkpoint exists without a committed audit event"),
        None => Ok(()),
        Some(_) if !checkpoint.exists() => bail!("committed audit events have no checkpoint"),
        Some((segment, event_hash, receipt)) => {
            let record: CheckpointRecord =
                strict_json(&read_owner_file(checkpoint)?, "WORM checkpoint")?;
            if record.version != "v1"
                || record.segment != segment
                || record.event_hash != event_hash
                || record.receipt != receipt
            {
                bail!("WORM checkpoint does not match the committed audit chain");
            }
            Ok(())
        }
    }
}

fn checkpoint_tx(
    command: &Path,
    checkpoint: &Path,
    tx: Transaction<'_>,
    kind: &str,
    subject_hash: &str,
) -> Result<()> {
    let previous: String = tx
        .query_row(
            "SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_default();
    let at = now()?;
    let material = format!("v1|{previous}|{at}|{kind}|{subject_hash}");
    let event_hash = hash_hex(material.as_bytes());
    let mut child = Command::new(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("start WORM receipt provider")?;
    child
        .stdin
        .take()
        .context("WORM stdin")?
        .write_all(event_hash.as_bytes())?;
    let out = child.wait_with_output()?;
    let receipt = String::from_utf8(out.stdout)?.trim().to_string();
    if !out.status.success() || receipt.is_empty() || receipt.len() > 4096 {
        bail!("external WORM receipt refused checkpoint");
    }
    let segment = at / 86_400;
    tx.execute("INSERT INTO events(segment,at,kind,subject_hash,prev_hash,event_hash,receipt) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![segment,at,kind,subject_hash,previous,event_hash,receipt])?;
    let parent = checkpoint.parent().context("checkpoint parent")?;
    let mut temp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(parent.join(format!(".checkpoint-{event_hash}")))?;
    temp.write_all(
        json!({"version":"v1","segment":segment,"event_hash":event_hash,"receipt":receipt})
            .to_string()
            .as_bytes(),
    )?;
    temp.sync_all()?;
    let temp_path = parent.join(format!(".checkpoint-{event_hash}"));
    fs::rename(&temp_path, checkpoint)?;
    tx.commit()?;
    Ok(())
}
fn hash_file(path: &Path) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
#[cfg(target_os = "linux")]
fn peer_identity(stream: &UnixStream) -> Result<(u32, u32, i32)> {
    let fd = std::os::fd::AsRawFd::as_raw_fd(stream);
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut _,
            &mut len,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((cred.uid, cred.gid, cred.pid))
}
#[cfg(target_os = "macos")]
fn peer_identity(stream: &UnixStream) -> Result<(u32, u32, i32)> {
    use std::os::fd::AsRawFd;
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut pid: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    const SOL_LOCAL: i32 = 0;
    const LOCAL_PEERPID: i32 = 2;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut _ as *mut _,
            &mut len,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((uid, gid, pid))
}
#[cfg(target_os = "linux")]
fn peer_process(pid: i32) -> Result<(PathBuf, u64)> {
    let path = fs::read_link(format!("/proc/{pid}/exe")).context("resolve peer executable")?;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = stat.rfind(')').context("invalid peer stat")?;
    let start = stat[close + 2..]
        .split_whitespace()
        .nth(19)
        .context("peer start time missing")?
        .parse()?;
    Ok((path, start))
}
#[cfg(target_os = "macos")]
fn peer_process(pid: i32) -> Result<(PathBuf, u64)> {
    #[repr(C)]
    struct BsdInfo {
        flags: u32,
        status: u32,
        xstatus: u32,
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        ruid: u32,
        rgid: u32,
        svuid: u32,
        svgid: u32,
        rfu: u32,
        comm: [u8; 16],
        name: [u8; 32],
        nfiles: u32,
        pgid: u32,
        pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        nice: i32,
        start_sec: u64,
        start_usec: u64,
    }
    extern "C" {
        fn proc_pidpath(pid: i32, buffer: *mut libc::c_void, buffersize: u32) -> i32;
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: i32,
        ) -> i32;
    }
    let mut pathbuf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe { proc_pidpath(pid, pathbuf.as_mut_ptr() as *mut _, pathbuf.len() as u32) };
    if n <= 0 {
        bail!("resolve peer executable")
    };
    pathbuf.truncate(n as usize);
    let mut info: BsdInfo = unsafe { std::mem::zeroed() };
    const PROC_PIDTBSDINFO: i32 = 3;
    let got = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<BsdInfo>() as i32,
        )
    };
    if got != std::mem::size_of::<BsdInfo>() as i32 || info.start_sec == 0 {
        bail!("resolve peer process start");
    }
    Ok((
        PathBuf::from(String::from_utf8(pathbuf)?),
        info.start_sec
            .saturating_mul(1_000_000)
            .saturating_add(info.start_usec),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(purpose: &str, resource: &str, target: &str) -> Rule {
        Rule {
            purpose: purpose.into(),
            resource: resource.into(),
            target: target.into(),
            max_ttl_seconds: 60,
            max_uses: 1,
            delegation_depth: 0,
        }
    }

    struct Fixture {
        broker: Broker,
        root: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn fixture_bound() -> Rule {
        Rule {
            purpose: "weles.browser.fill".into(),
            resource: "origin:https://example.test".into(),
            target: "weles".into(),
            max_ttl_seconds: 3_600,
            max_uses: 10,
            delegation_depth: 2,
        }
    }

    fn fixture() -> Fixture {
        let at = now().expect("wall clock");
        let bound = fixture_bound();
        let policy = Policy {
            version: "v1".into(),
            sequence: 1,
            environment: "test".into(),
            worm_command_sha256: String::new(),
            roles: BTreeMap::from([("operator".into(), vec![bound.clone()])]),
            agents: BTreeMap::from([(
                "alice".into(),
                Agent {
                    roles: vec!["operator".into()],
                },
            )]),
            agent_grants: BTreeMap::from([(
                "alice".into(),
                vec![Grant {
                    grant_id: "active-grant".into(),
                    not_before: at - 60,
                    expires_at: at + 3_600,
                    revoked: false,
                    rules: vec![bound.clone()],
                }],
            )]),
            environment_allow: vec![bound],
            deny: Vec::new(),
            leases: BTreeMap::from([(
                "alice".into(),
                Lease {
                    not_before: at - 60,
                    expires_at: at + 3_600,
                },
            )]),
            rate: Rate {
                issue_per_minute: 100,
                redeem_failures_per_minute: 100,
            },
        };

        let conn = Connection::open_in_memory().expect("in-memory capability database");
        conn.execute_batch(
            "CREATE TABLE capabilities(id_hash TEXT PRIMARY KEY,agent TEXT NOT NULL,purpose TEXT NOT NULL,resource TEXT NOT NULL,target TEXT NOT NULL,authorization_id TEXT,issued_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,max_uses INTEGER NOT NULL,uses INTEGER NOT NULL DEFAULT 0,depth INTEGER NOT NULL,parent_hash TEXT,cancelled INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE replay(id_hash TEXT NOT NULL,nonce_hash TEXT NOT NULL,PRIMARY KEY(id_hash,nonce_hash));
             CREATE TABLE counters(kind TEXT NOT NULL,subject TEXT NOT NULL,window INTEGER NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(kind,subject,window));
             CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,segment INTEGER NOT NULL,at INTEGER NOT NULL,kind TEXT NOT NULL,subject_hash TEXT NOT NULL,prev_hash TEXT NOT NULL,event_hash TEXT NOT NULL,receipt TEXT NOT NULL);",
        ).expect("capability schema");

        let mut random = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let root = std::env::temp_dir().join(format!(
            "skarbiec-capability-test-{}-{}",
            std::process::id(),
            u64::from_ne_bytes(random),
        ));
        fs::create_dir(&root).expect("fixture directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("fixture permissions");
        let worm_command = root.join("worm-receipt");
        let mut script = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&worm_command)
            .expect("WORM fixture script");
        script
            .write_all(b"#!/bin/sh\ncat >/dev/null\nprintf receipt\n")
            .expect("write WORM fixture script");
        drop(script);

        let broker = Broker {
            policy,
            registry: Registry {
                version: "v1".into(),
                sequence: 1,
                workloads: BTreeMap::new(),
            },
            conn,
            socket: root.join("broker.sock"),
            socket_gid: 0,
            worm_command,
            checkpoint: root.join("checkpoint.json"),
        };
        Fixture { broker, root }
    }

    fn insert_active_capability(fixture: &Fixture, id_hash: &str, max_uses: u64) {
        fixture.broker.conn.execute(
            "INSERT INTO capabilities(id_hash,agent,purpose,resource,target,issued_at,expires_at,max_uses,uses,depth,parent_hash,cancelled) VALUES(?1,'alice','weles.browser.fill','origin:https://example.test','weles',?2,?3,?4,0,0,NULL,0)",
            params![id_hash, now().unwrap(), now().unwrap() + 60, max_uses],
        ).expect("active capability fixture");
    }

    fn redemption_state(fixture: &Fixture, id_hash: &str) -> (u64, u64, u64) {
        fixture.broker.conn.query_row(
            "SELECT uses,(SELECT count(*) FROM replay WHERE id_hash=?1),(SELECT count(*) FROM events) FROM capabilities WHERE id_hash=?1",
            [id_hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).expect("observable redemption state")
    }

    #[test]
    fn redemption_commit_atomically_enforces_binding_replay_and_max_uses() {
        let mut fixture = fixture();
        let id_hash = hash_hex(b"max-use-capability");
        insert_active_capability(&fixture, &id_hash, 2);

        for (case, target, agent, resource, nonce_hash) in [
            (
                "target",
                "brama",
                "alice",
                "origin:https://example.test",
                hash_hex(b"wrong-target-nonce"),
            ),
            (
                "agent",
                "weles",
                "mallory",
                "origin:https://example.test",
                hash_hex(b"wrong-agent-nonce"),
            ),
            (
                "resource",
                "weles",
                "alice",
                "origin:https://other.test",
                hash_hex(b"wrong-resource-nonce"),
            ),
        ] {
            assert!(
                commit_redemption(
                    &mut fixture.broker.conn,
                    &fixture.broker.worm_command,
                    &fixture.broker.checkpoint,
                    &id_hash,
                    &nonce_hash,
                    target,
                    agent,
                    resource,
                    None,
                )
                .is_err(),
                "{case} mismatch must deny redemption",
            );
        }
        assert_eq!(
            redemption_state(&fixture, &id_hash),
            (0, 0, 0),
            "binding mismatches must not consume or audit the capability"
        );

        let first_nonce = hash_hex(b"first-nonce");
        commit_redemption(
            &mut fixture.broker.conn,
            &fixture.broker.worm_command,
            &fixture.broker.checkpoint,
            &id_hash,
            &first_nonce,
            "weles",
            "alice",
            "origin:https://example.test",
            None,
        )
        .expect("first redemption");
        assert_eq!(
            redemption_state(&fixture, &id_hash),
            (1, 1, 1),
            "first nonce must atomically consume one use, reserve replay, and audit"
        );

        assert!(
            commit_redemption(
                &mut fixture.broker.conn,
                &fixture.broker.worm_command,
                &fixture.broker.checkpoint,
                &id_hash,
                &first_nonce,
                "weles",
                "alice",
                "origin:https://example.test",
                None,
            )
            .is_err(),
            "replayed nonce must be rejected"
        );
        assert_eq!(
            redemption_state(&fixture, &id_hash),
            (1, 1, 1),
            "replay rejection must roll back all redemption state"
        );

        commit_redemption(
            &mut fixture.broker.conn,
            &fixture.broker.worm_command,
            &fixture.broker.checkpoint,
            &id_hash,
            &hash_hex(b"second-nonce"),
            "weles",
            "alice",
            "origin:https://example.test",
            None,
        )
        .expect("second redemption reaches max use");
        assert_eq!(
            redemption_state(&fixture, &id_hash),
            (2, 2, 2),
            "second unique nonce must reach max use atomically"
        );

        assert!(
            commit_redemption(
                &mut fixture.broker.conn,
                &fixture.broker.worm_command,
                &fixture.broker.checkpoint,
                &id_hash,
                &hash_hex(b"fresh-nonce-at-limit"),
                "weles",
                "alice",
                "origin:https://example.test",
                None,
            )
            .is_err(),
            "fresh nonce must be rejected after max use"
        );
        assert_eq!(
            redemption_state(&fixture, &id_hash),
            (2, 2, 2),
            "max-use rejection must not reserve replay, consume, or audit"
        );
    }

    #[test]
    fn malformed_scalar_extraction_does_not_consume_redemption_state() {
        let fixture = fixture();
        let id_hash = hash_hex(b"malformed-scalar-capability");
        insert_active_capability(&fixture, &id_hash, 1);

        assert!(
            extract_scalar_secret(
                json!({"type": "api-token", "value": "secret", "metadata": "not-dedicated"})
            )
            .is_err(),
            "non-dedicated object must fail scalar extraction before redemption commit",
        );
        assert_eq!(
            redemption_state(&fixture, &id_hash),
            (0, 0, 0),
            "failed extraction must leave uses, replay, and audit untouched"
        );
    }

    fn request(ttl: u64) -> Rule {
        let mut requested = fixture_bound();
        requested.max_ttl_seconds = ttl;
        requested.max_uses = 3;
        requested.delegation_depth = 1;
        requested
    }

    fn assert_authorization_denied(broker: &Broker, requested: &Rule, expected: &str) {
        let error = broker
            .authorized("alice", requested)
            .expect_err("authorization must be denied");
        assert!(
            error.to_string().contains(expected),
            "unexpected authorization error: {error:#}"
        );
    }

    #[test]
    fn authorization_requires_role_environment_lease_and_active_bounded_grant() {
        let requested = request(60);
        assert!(
            fixture().broker.authorized("alice", &requested).is_ok(),
            "complete authorization intersection must allow the request"
        );

        let mut missing_role = fixture();
        missing_role
            .broker
            .policy
            .agents
            .get_mut("alice")
            .unwrap()
            .roles
            .clear();
        assert_authorization_denied(&missing_role.broker, &requested, "no active bounded grant");

        let mut outside_environment = fixture();
        outside_environment.broker.policy.environment_allow.clear();
        assert_authorization_denied(
            &outside_environment.broker,
            &requested,
            "outside environment constraints",
        );

        let mut missing_lease = fixture();
        missing_lease.broker.policy.leases.remove("alice");
        assert_authorization_denied(&missing_lease.broker, &requested, "no active lease");

        let mut missing_grant = fixture();
        missing_grant.broker.policy.agent_grants.remove("alice");
        assert_authorization_denied(&missing_grant.broker, &requested, "no active bounded grant");

        let mut revoked_grant = fixture();
        revoked_grant
            .broker
            .policy
            .agent_grants
            .get_mut("alice")
            .unwrap()[0]
            .revoked = true;
        assert_authorization_denied(&revoked_grant.broker, &requested, "no active bounded grant");

        let mut expired_grant = fixture();
        expired_grant
            .broker
            .policy
            .agent_grants
            .get_mut("alice")
            .unwrap()[0]
            .expires_at = now().unwrap() - 1;
        assert_authorization_denied(&expired_grant.broker, &requested, "no active bounded grant");

        let mut short_lease = fixture();
        short_lease
            .broker
            .policy
            .leases
            .get_mut("alice")
            .unwrap()
            .expires_at = now().unwrap() + 120;
        assert_authorization_denied(&short_lease.broker, &request(180), "lease inactive");

        let mut short_grant = fixture();
        short_grant
            .broker
            .policy
            .agent_grants
            .get_mut("alice")
            .unwrap()[0]
            .expires_at = now().unwrap() + 120;
        assert_authorization_denied(
            &short_grant.broker,
            &request(180),
            "no active bounded grant",
        );
    }

    #[test]
    fn delegation_persists_bounds_and_atomically_reserves_parent_uses() {
        let mut fixture = fixture();
        let parent = fixture
            .broker
            .issue(
                "alice",
                "weles.browser.fill",
                "origin:https://example.test",
                "weles",
                600,
                3,
                2,
            )
            .expect("issue parent capability");
        let parent_hash = hash_hex(parent.as_bytes());
        let child = fixture
            .broker
            .delegate("alice", &parent, "weles", 300, 2)
            .expect("bounded delegation");
        let child_hash = hash_hex(child.as_bytes());

        let (stored_parent, target, depth, child_expires): (String, String, u32, u64) = fixture
            .broker
            .conn
            .query_row(
                "SELECT parent_hash,target,depth,expires_at FROM capabilities WHERE id_hash=?1",
                [&child_hash],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("persisted child capability");
        let (parent_expires, parent_uses): (u64, u64) = fixture
            .broker
            .conn
            .query_row(
                "SELECT expires_at,uses FROM capabilities WHERE id_hash=?1",
                [&parent_hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("persisted parent capability");
        assert_eq!(
            stored_parent, parent_hash,
            "child must retain its parent hash"
        );
        assert_eq!(
            target, "weles",
            "delegation must preserve the parent target"
        );
        assert_eq!(depth, 1, "delegation must consume exactly one depth level");
        assert!(
            child_expires <= parent_expires,
            "child TTL must not outlive its parent"
        );
        assert_eq!(
            parent_uses, 2,
            "delegation must reserve the child's uses from its parent"
        );

        assert!(
            fixture
                .broker
                .delegate("alice", &parent, "brama", 60, 1)
                .is_err(),
            "delegation must not change target"
        );
        let excessive_ttl = parent_expires
            .saturating_sub(now().unwrap())
            .saturating_add(1);
        assert!(
            fixture
                .broker
                .delegate("alice", &parent, "weles", excessive_ttl, 1)
                .is_err(),
            "delegation must not outlive its parent"
        );
        assert!(
            fixture
                .broker
                .delegate("alice", &parent, "weles", 60, 2)
                .is_err(),
            "delegation must not overallocate remaining uses"
        );

        let (uses_after_failures, children): (u64, u64) = fixture.broker.conn.query_row(
            "SELECT uses,(SELECT count(*) FROM capabilities WHERE parent_hash=?1) FROM capabilities WHERE id_hash=?1",
            [&parent_hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).expect("post-failure capability state");
        assert_eq!(
            uses_after_failures, 2,
            "rejected delegations must not reserve parent uses"
        );
        assert_eq!(
            children, 1,
            "rejected delegations must not persist children"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ensure_redemption_supported_rejects_macos() {
        assert!(ensure_redemption_supported().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ensure_redemption_supported_accepts_linux() {
        assert!(ensure_redemption_supported().is_ok());
    }

    #[test]
    fn signed_configuration_sequence_only_accepts_strictly_newer_grants() {
        assert!(strictly_newer(8, 7).is_err(), "rollback must be rejected");
        assert!(!strictly_newer(8, 8).expect("equal sequence is valid"));
        assert!(strictly_newer(8, 9).expect("newer sequence is valid"));
    }

    #[test]
    fn anomaly_event_fires_only_when_the_threshold_is_first_crossed() {
        let limit = 10;
        let cases = [
            (limit - 1, false, "below limit"),
            (limit, false, "at limit"),
            (limit + 1, true, "first over limit"),
            (limit + 2, false, "subsequent over limit"),
        ];

        for (count, expected, case) in cases {
            assert_eq!(anomaly_threshold_crossed(count, limit), expected, "{case}");
        }
    }

    #[test]
    fn anomaly_threshold_saturates_fail_closed_at_u64_max() {
        assert!(anomaly_threshold_crossed(u64::MAX, u64::MAX));
        assert!(!anomaly_threshold_crossed(u64::MAX - 1, u64::MAX));
    }

    #[test]
    fn accepts_every_capability_contract_taxonomy_entry() {
        let accepted = [
            ("weles.browser.fill", "origin:https://example.test", "weles"),
            ("weles.captcha.solve", "provider:turnstile", "weles"),
            ("weles.sms.verify", "provider:twilio", "weles"),
            ("weles.proxy.authenticate", "proxy:edge", "weles"),
            ("weles.brama.sign", "brama:primary", "weles"),
            ("weles.brama.sign", "agent:checkout", "weles"),
            (
                "most.service.authenticate",
                "credential:most/service",
                "most-service",
            ),
            (
                "most.database.connect",
                "credential:most/database",
                "most-service",
            ),
            (
                "most.twilio.authenticate",
                "credential:most/twilio",
                "most-service",
            ),
            (
                "most.attachment.sign",
                "credential:most/attachment-signing",
                "most-service",
            ),
            (
                "most.remote-worker.authenticate",
                "credential:most/remote-worker",
                "most-service",
            ),
            ("brama.provider.authenticate", "provider:openai", "brama"),
            ("brama.supabase.connect", "supabase:production", "brama"),
            ("brama.request.sign", "agent:checkout", "brama"),
            (
                "singularity.brama.bootstrap",
                "brama:primary",
                "singularity-bootstrap",
            ),
            (
                "singularity.most.bootstrap",
                "most:primary",
                "singularity-bootstrap",
            ),
        ];

        for (purpose, resource, target) in accepted {
            assert!(
                validate_rule(&rule(purpose, resource, target), false).is_ok(),
                "contract taxonomy entry was rejected: {target}/{purpose}/{resource}"
            );
        }
    }

    #[test]
    fn rejects_noncanonical_capability_scopes() {
        let rejected = [
            (
                "cross-target purpose reuse",
                "weles.browser.fill",
                "origin:https://example.test",
                "brama",
            ),
            (
                "wrong resource prefix",
                "weles.browser.fill",
                "provider:example",
                "weles",
            ),
            (
                "namespace-only resource",
                "weles.browser.fill",
                "origin:",
                "weles",
            ),
            (
                "purpose wildcard",
                "*",
                "origin:https://example.test",
                "weles",
            ),
            (
                "resource wildcard",
                "weles.browser.fill",
                "origin:*",
                "weles",
            ),
            (
                "target wildcard",
                "weles.browser.fill",
                "origin:https://example.test",
                "*",
            ),
        ];

        for (case, purpose, resource, target) in rejected {
            assert!(
                validate_rule(&rule(purpose, resource, target), false).is_err(),
                "{case} unexpectedly passed validation"
            );
        }
    }

    #[test]
    fn redeem_request_rejects_unknown_fields() {
        let request = br#"{
            "version":"skarbiec.redeem.v1",
            "capability_id":"0000000000000000000000000000000000000000000000000000000000000000",
            "nonce":"nonce",
            "workload_id":"workload",
            "proof":"proof",
            "unexpected":"must-fail-closed"
        }"#;

        assert!(strict_json::<BrokerRequest>(request, "redeem request").is_err());
    }

    fn bounded_rule() -> Rule {
        Rule {
            purpose: "weles.browser.fill".into(),
            resource: "origin:https://example.test".into(),
            target: "weles".into(),
            max_ttl_seconds: 600,
            max_uses: 10,
            delegation_depth: 2,
        }
    }

    fn active_policy() -> Policy {
        let at = now().unwrap();
        let bound = bounded_rule();
        Policy {
            version: "v1".into(),
            sequence: 1,
            environment: "test".into(),
            worm_command_sha256: String::new(),
            roles: BTreeMap::from([("deployer".into(), vec![bound.clone()])]),
            agents: BTreeMap::from([(
                "agent-a".into(),
                Agent {
                    roles: vec!["deployer".into()],
                },
            )]),
            agent_grants: BTreeMap::from([(
                "agent-a".into(),
                vec![Grant {
                    grant_id: "grant-a".into(),
                    not_before: at.saturating_sub(60),
                    expires_at: at + 3_600,
                    revoked: false,
                    rules: vec![bound.clone()],
                }],
            )]),
            environment_allow: vec![bound],
            deny: vec![],
            leases: BTreeMap::from([(
                "agent-a".into(),
                Lease {
                    not_before: at.saturating_sub(60),
                    expires_at: at + 3_600,
                },
            )]),
            rate: Rate {
                issue_per_minute: 2,
                redeem_failures_per_minute: 2,
            },
        }
    }

    fn test_broker(policy: Policy) -> Broker {
        Broker {
            policy,
            registry: Registry {
                version: "v1".into(),
                sequence: 1,
                workloads: BTreeMap::new(),
            },
            conn: Connection::open_in_memory().unwrap(),
            socket: PathBuf::new(),
            socket_gid: 0,
            worm_command: PathBuf::new(),
            checkpoint: PathBuf::new(),
        }
    }

    fn requested_rule() -> Rule {
        let mut requested = bounded_rule();
        requested.max_ttl_seconds = 60;
        requested.max_uses = 1;
        requested.delegation_depth = 0;
        requested
    }

    #[test]
    fn authorization_requires_active_lease_role_grant_environment_and_no_deny() {
        let requested = requested_rule();
        assert!(test_broker(active_policy())
            .authorized("agent-a", &requested)
            .is_ok());

        let mut no_lease = active_policy();
        no_lease.leases.clear();
        assert!(test_broker(no_lease)
            .authorized("agent-a", &requested)
            .unwrap_err()
            .to_string()
            .contains("no active lease"));

        let mut role_too_narrow = active_policy();
        role_too_narrow.roles.get_mut("deployer").unwrap()[0].max_ttl_seconds = 30;
        assert!(test_broker(role_too_narrow)
            .authorized("agent-a", &requested)
            .unwrap_err()
            .to_string()
            .contains("no active bounded grant"));

        let mut revoked_grant = active_policy();
        revoked_grant.agent_grants.get_mut("agent-a").unwrap()[0].revoked = true;
        assert!(test_broker(revoked_grant)
            .authorized("agent-a", &requested)
            .unwrap_err()
            .to_string()
            .contains("no active bounded grant"));

        let mut outside_environment = active_policy();
        outside_environment.environment_allow[0].max_ttl_seconds = 30;
        assert!(test_broker(outside_environment)
            .authorized("agent-a", &requested)
            .unwrap_err()
            .to_string()
            .contains("outside environment constraints"));

        let mut denied = active_policy();
        denied.deny.push(requested.clone());
        assert!(test_broker(denied)
            .authorized("agent-a", &requested)
            .unwrap_err()
            .to_string()
            .contains("denied by policy"));
    }

    #[test]
    fn issue_rate_boundary_blocks_the_first_request_over_limit() {
        let broker = test_broker(active_policy());
        broker.conn.execute_batch("CREATE TABLE counters(kind TEXT NOT NULL,subject TEXT NOT NULL,window INTEGER NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(kind,subject,window));").unwrap();

        assert!(broker.rate_available("issue", "agent-a", 2).unwrap());
        assert!(broker.rate("issue", "agent-a", 2).is_ok());
        assert!(broker.rate("issue", "agent-a", 2).is_ok());
        assert!(!broker.rate_available("issue", "agent-a", 2).unwrap());
        assert!(broker
            .rate("issue", "agent-a", 2)
            .unwrap_err()
            .to_string()
            .contains("rate limit exceeded"));
    }

    #[test]
    fn status_marks_expired_and_max_use_capabilities_inactive() {
        let broker = test_broker(active_policy());
        broker.conn.execute_batch("CREATE TABLE capabilities(id_hash TEXT PRIMARY KEY,expires_at INTEGER NOT NULL,max_uses INTEGER NOT NULL,uses INTEGER NOT NULL,cancelled INTEGER NOT NULL);").unwrap();
        let at = now().unwrap();
        for (id, expires, uses) in [
            ("remaining", at + 60, 1_u64),
            ("maxed", at + 60, 2),
            ("expired", at.saturating_sub(1), 0),
        ] {
            broker.conn.execute(
                "INSERT INTO capabilities(id_hash,expires_at,max_uses,uses,cancelled) VALUES(?1,?2,2,?3,0)",
                params![hash_hex(id.as_bytes()), expires, uses],
            ).unwrap();
        }

        assert_eq!(
            broker.status("remaining").unwrap(),
            json!({"known":true,"active":true,"expires_at":at + 60,"remaining_uses":1})
        );
        assert_eq!(
            broker.status("maxed").unwrap(),
            json!({"known":true,"active":false,"expires_at":at + 60,"remaining_uses":0})
        );
        assert_eq!(
            broker.status("expired").unwrap(),
            json!({"known":true,"active":false,"expires_at":at.saturating_sub(1),"remaining_uses":2})
        );
    }

    #[test]
    fn delegation_rejects_target_ttl_use_and_depth_expansion() {
        let mut broker = test_broker(active_policy());
        broker.conn.execute_batch("CREATE TABLE capabilities(id_hash TEXT PRIMARY KEY,agent TEXT NOT NULL,purpose TEXT NOT NULL,resource TEXT NOT NULL,target TEXT NOT NULL,authorization_id TEXT,expires_at INTEGER NOT NULL,max_uses INTEGER NOT NULL,uses INTEGER NOT NULL,depth INTEGER NOT NULL,cancelled INTEGER NOT NULL);").unwrap();
        let expires = now().unwrap() + 30;
        for (id, depth) in [
            ("no-depth", 0_u32),
            ("wrong-target", 1),
            ("long-ttl", 1),
            ("too-many-uses", 1),
        ] {
            broker.conn.execute(
                "INSERT INTO capabilities(id_hash,agent,purpose,resource,target,expires_at,max_uses,uses,depth,cancelled) VALUES(?1,'agent-a','weles.browser.fill','origin:https://example.test','weles',?2,2,1,?3,0)",
                params![hash_hex(id.as_bytes()), expires, depth],
            ).unwrap();
        }

        assert!(broker
            .delegate("agent-a", "no-depth", "weles", 1, 1)
            .is_err());
        assert!(broker
            .delegate("agent-a", "wrong-target", "brama", 1, 1)
            .is_err());
        assert!(broker
            .delegate("agent-a", "long-ttl", "weles", 31, 1)
            .is_err());
        assert!(broker
            .delegate("agent-a", "too-many-uses", "weles", 1, 2)
            .is_err());
    }
    #[test]
    fn scalar_secret_extraction_returns_raw_value_bytes() {
        let cases = [
            (json!("line\nsecret-é"), b"line\nsecret-\xc3\xa9".as_slice()),
            (
                json!({"type": "api-token", "value": "sk_live\nvalue"}),
                b"sk_live\nvalue".as_slice(),
            ),
        ];

        for (item, expected) in cases {
            assert_eq!(
                extract_scalar_secret(item).expect("dedicated scalar secret"),
                expected
            );
        }
    }

    #[test]
    fn scalar_secret_extraction_rejects_empty_non_scalar_and_non_dedicated_objects() {
        let rejected = [
            ("empty string", json!("")),
            ("null", Value::Null),
            ("boolean", json!(true)),
            ("number", json!(7)),
            ("array", json!(["secret"])),
            (
                "empty object value",
                json!({"type": "api-token", "value": ""}),
            ),
            (
                "non-string object value",
                json!({"type": "api-token", "value": 7}),
            ),
            ("missing type", json!({"value": "secret"})),
            (
                "sibling field",
                json!({"type": "api-token", "value": "secret", "metadata": "must-not-leak"}),
            ),
        ];

        for (case, item) in rejected {
            assert!(
                extract_scalar_secret(item).is_err(),
                "{case} must not be exposed as a scalar secret"
            );
        }
    }

    #[test]
    fn same_target_workloads_only_allow_their_exact_agent_ids() {
        let workload = |agent_ids: Vec<&str>| Workload {
            target: "weles".into(),
            uid: 1000,
            gid: 1000,
            executable_path: "/usr/bin/weles".into(),
            executable_sha256: "00".repeat(32),
            proof_key: "proof-key".into(),
            agent_ids: agent_ids.into_iter().map(str::to_owned).collect(),
        };
        let checkout = workload(vec!["checkout-agent"]);
        let support = workload(vec!["support-agent"]);

        assert!(workload_allows_agent(&checkout, "checkout-agent"));
        assert!(!workload_allows_agent(&checkout, "support-agent"));
        assert!(workload_allows_agent(&support, "support-agent"));
        assert!(!workload_allows_agent(&support, "checkout-agent"));
        assert!(!workload_allows_agent(&checkout, "checkout-agent-shadow"));
    }

    fn valid_redeem_request_bytes() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": WIRE_VERSION,
            "capability_id": "0".repeat(64),
            "nonce": "nonce-1",
            "workload_id": "weles-primary",
            "proof": "proof-1"
        }))
        .unwrap()
    }

    #[test]
    fn redeem_request_requires_one_newline_frame_followed_by_eof() {
        use std::net::Shutdown;

        let (reader, mut writer) = UnixStream::pair().unwrap();
        let mut request = valid_redeem_request_bytes();
        request.push(b'\n');
        writer.write_all(&request).unwrap();
        writer.shutdown(Shutdown::Write).unwrap();
        let parsed =
            read_redeem_request(&reader).expect("newline-delimited request followed by EOF");
        assert_eq!(parsed.version, WIRE_VERSION);
        assert_eq!(parsed.capability_id, "0".repeat(64));
        assert_eq!(parsed.nonce, "nonce-1");
        assert_eq!(parsed.workload_id, "weles-primary");
        assert_eq!(parsed.proof, "proof-1");

        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(&request).unwrap();
        writer.write_all(b"x").unwrap();
        writer.shutdown(Shutdown::Write).unwrap();
        let error = read_redeem_request(&reader)
            .err()
            .expect("trailing bytes must be rejected");
        assert!(error.to_string().contains("trailing bytes"));

        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(&request).unwrap();
        let error = read_redeem_request(&reader)
            .err()
            .expect("missing EOF must be rejected");
        assert!(error.to_string().contains("must end with EOF"));
    }

    #[test]
    fn policy_and_workload_registry_require_distinct_trust_keys() {
        use ed25519_dalek::SigningKey;

        let policy = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let same = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let workload = SigningKey::from_bytes(&[2; 32]).verifying_key();

        assert!(ensure_distinct_trust_roots(&policy, &same).is_err());
        assert!(ensure_distinct_trust_roots(&policy, &workload).is_ok());
    }

    #[test]
    fn broker_availability_turns_false_when_issue_rate_is_exhausted() {
        let mut fixture = fixture();
        fixture.broker.policy.rate.issue_per_minute = 2;
        let broker = &fixture.broker;
        let available = || {
            broker.available(
                "alice",
                "weles.browser.fill",
                "origin:https://example.test",
                "weles",
                60,
                1,
            )
        };

        assert!(
            available(),
            "an authorized request below the issue limit must be available"
        );
        broker.rate("issue", "alice", 2).unwrap();
        assert!(available(), "one remaining issue must still be available");
        broker.rate("issue", "alice", 2).unwrap();
        assert!(
            !available(),
            "availability must close when the issue limit is exhausted"
        );
    }
}
