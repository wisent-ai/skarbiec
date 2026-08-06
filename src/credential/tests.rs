// Contract tests for the credential lifecycle: the v3 wire, the write-once
// directory contract, the `--expect-*` cross-check, provider effects,
// quarantine, approvals, receipts, adoption, capabilities, and the rotate /
// reset split.
//
// Every test owns a throwaway vault, keyring, audit journal and Weles bridge
// under a private temporary directory and removes all of it again on drop.
// Nothing here reads or writes the operator's real vault, keyring, audit
// journal or service directory, and nothing reaches the network: the bridge is
// a transport stub that reads one request from stdin and prints one prepared
// reply, so every check Skarbiec makes is made for real.

use anyhow::Result;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::access::tokens;
use crate::core::vault::{ManagedWrite, Vault};
use crate::core::{crypto, schema};

use super::adopt::{
    candidate_hidden, managed_read, stage_adopted_candidate, trash_adopted_item, AdoptShape,
    AdoptStaging, ManagedRead,
};
use super::common::TOKEN_FILE_ENV;
use super::directory::{checked_directory, sealed_record, wire_directory};
use super::eligibility::{
    BLOCKER_LEGACY_ENVELOPE, BLOCKER_NONCANONICAL_FIELD, BLOCKER_NO_DIRECTORY_CONTRACT,
    BLOCKER_QUARANTINED,
};
use super::quarantine::{enforce_provider_effect, enforce_retry_barrier};
use super::receipt::{approval_expired, checked_approval, checked_receipt, receipt_matches};
use super::state::{
    authorize_managed_write, context_block, item_revision, lifecycle_state,
    pending_matches_request, request_item_id, save_request,
};
use super::status::status_once;
use super::wire::{
    contract_field, provider_contract, request_payload, sanitized_response, BRIDGE_ENV,
};
use super::{
    dispatch, ACCOUNT_PROVIDER, EXPECTATION_MISMATCH, FIELD_CONTRACT_MISMATCH, IDENTITY_PROVIDER,
    QUARANTINE_CONFIRMATION, STATE_ADOPTING, STATE_MANAGED, STATE_QUARANTINED, STATE_UNMANAGED,
};

// The process-wide environment (keyring, vault location, audit journal, bridge)
// is a single resource: credential tests take it one at a time.
static LAB_LOCK: Mutex<()> = Mutex::new(());
static NEXT_LAB: AtomicU64 = AtomicU64::new(u64::MIN);

const OWNER_UID: &str = "skarbiec-credential-tests";
const CONSUMER: &str = "weles-agent";
const CREDENTIAL: &str = "entra-admin";
const GENERIC_PROVIDER: &str = "github";

// The field every directory credential contract writes, and the other name
// one real item carries for the same secret.
const CANONICAL_FIELD: &str = "password";
const NONCANONICAL_FIELD: &str = "login_password";

const TENANT_ID: &str = "11111111-2222-3333-4444-555555555555";
const OBJECT_ID: &str = "66666666-7777-8888-9999-aaaaaaaaaaaa";
const ACCOUNT_UPN: &str = "principal@contoso.example";
const OTHER_TENANT_ID: &str = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
const OTHER_OBJECT_ID: &str = "12345678-90ab-cdef-1234-567890abcdef";
const OTHER_ACCOUNT_UPN: &str = "someone.else@contoso.example";

const WIRE_V1: &str = "skarbiec.credential-operation.v1";
const WIRE_V2: &str = "skarbiec.credential-operation.v2";
const WIRE_V3: &str = "skarbiec.credential-operation.v3";

const EVIDENCE_DIGEST: &str = "6f4b1c2d3e5a70819243aabbccddeeff00112233445566778899aabbccddeeff";
const SAMPLE_REQUEST_ID: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff";
const ACTION_LOG_ID: &str = "weles-action-log-1";
const REPLY_REQUEST_ID: &str = "__REQUEST_ID__";
const FUTURE_EXPIRY: &str = "2999-01-01T00:00:00Z";
const PAST_EXPIRY: &str = "2020-01-01T00:00:00Z";

fn one() -> u64 {
    std::iter::once(()).count() as u64
}

fn octal(text: &str) -> u32 {
    let radix: u32 = "8".parse().expect("octal radix");
    u32::from_str_radix(text, radix).expect("octal permission mode")
}

fn flag_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

fn keys_of(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .expect("expected a JSON object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

fn text_of(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

// The reasons one `credential status` gives for refusing to call an item
// eligible, in the order it reports them.
fn blocker_reasons(status: &Value) -> Vec<String> {
    status
        .get("lifecycle_blockers")
        .and_then(Value::as_array)
        .expect("status carries a lifecycle blocker list")
        .iter()
        .map(|blocker| text_of(blocker, "reason"))
        .collect()
}

fn blocker_detail(status: &Value, reason: &str) -> String {
    status
        .get("lifecycle_blockers")
        .and_then(Value::as_array)
        .expect("status carries a lifecycle blocker list")
        .iter()
        .find(|blocker| text_of(blocker, "reason") == reason)
        .map(|blocker| text_of(blocker, "detail"))
        .unwrap_or_else(|| panic!("no {reason} blocker in {status}"))
}

// A refusal, with the exact reason it must name.
fn refusal<T: std::fmt::Debug>(result: Result<T>, expected: &str) -> String {
    let error = match result {
        Ok(value) => panic!("expected a refusal mentioning {expected}, got {value:?}"),
        Err(error) => error,
    };
    let text = format!("{error:#}");
    assert!(
        text.contains(expected),
        "refusal does not mention {expected}: {text}"
    );
    text
}

fn accepted<T>(result: Result<T>) -> T {
    result.unwrap_or_else(|error| panic!("expected acceptance, got refusal: {error:#}"))
}

// Lab directories are named after the process that owns them, so an
// abandoned one is recognisable and reapable.
const LAB_PREFIX: &str = "sk-cred-";

fn process_alive(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid])
        .status()
        .is_ok_and(|status| status.success())
}

// A hard-killed test run never gets to drop its lab, which leaves a keyring
// directory and a gpg-agent behind. Reap those before opening a new one so a
// crashed run cannot accumulate.
fn reap_abandoned_labs() {
    let Ok(entries) = fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    let own = std::process::id().to_string();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(owner) = name
            .strip_prefix(LAB_PREFIX)
            .and_then(|rest| rest.split('-').next())
        else {
            continue;
        };
        if owner == own || process_alive(owner) {
            continue;
        }
        let path = entry.path();
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", path.join("g"))
            .args(["--kill", "all"])
            .status();
        let _ = fs::remove_dir_all(&path);
    }
}

// One isolated credential lifecycle world: its own keyring, vault, audit
// journal and Weles bridge, all inside one private temporary directory.
struct Lab {
    root: PathBuf,
    gnupg: PathBuf,
    vault_path: PathBuf,
    _guard: MutexGuard<'static, ()>,
}

impl Lab {
    fn new() -> Self {
        let guard = LAB_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        reap_abandoned_labs();
        let sequence = NEXT_LAB.fetch_add(one(), Ordering::Relaxed);
        // The keyring path stays short on purpose: gpg-agent's socket lives
        // inside it and a long prefix overflows the unix socket name.
        let root =
            std::env::temp_dir().join(format!("{LAB_PREFIX}{}-{sequence}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let gnupg = root.join("g");
        fs::create_dir_all(&gnupg).expect("create the lab keyring directory");
        let private = fs::Permissions::from_mode(octal("700"));
        fs::set_permissions(&root, private.clone()).expect("protect the lab root");
        fs::set_permissions(&gnupg, private).expect("protect the lab keyring");
        let vault_path = root.join("skarbiec.vault.json");

        std::env::set_var("GNUPGHOME", &gnupg);
        std::env::set_var("HOME", &root);
        std::env::set_var("SKARBIEC_VAULT_FILE", &vault_path);
        std::env::set_var("SKARBIEC_AUDIT_FILE", root.join("audit.jsonl"));
        std::env::set_var("STADO_FORWARDS_DIR", root.join("no-forwards"));
        std::env::remove_var(BRIDGE_ENV);
        std::env::remove_var(TOKEN_FILE_ENV);
        std::env::remove_var("SKARBIEC_UNLOCK");
        std::env::remove_var("SKARBIEC_UNLOCK_FILE");

        let fingerprint = crypto::generate_key(OWNER_UID).expect("generate the lab key pair");
        Vault::create(
            vault_path.clone(),
            OWNER_UID,
            &fingerprint,
            // One key is both owner and recovery recipient: the lab never
            // exercises recovery, and a second key doubles fixture cost.
            &fingerprint,
        )
        .expect("create the lab vault");

        Self {
            root,
            gnupg,
            vault_path,
            _guard: guard,
        }
    }

    fn vault(&self) -> Vault {
        Vault::open(self.vault_path.clone()).expect("open the lab vault")
    }

    fn credential(&self, positionals: &[&str], pairs: &[(&str, &str)]) -> Result<Value> {
        let flags = flag_map(pairs);
        let words: Vec<String> = positionals.iter().map(|word| (*word).to_string()).collect();
        Ok(dispatch("credential", &flags, &words, &self.vault_path)?.unwrap_or(Value::Null))
    }

    fn lock_path(&self) -> PathBuf {
        self.vault_path.with_extension("credential-operation.lock")
    }

    // The Weles bridge stub: one prepared reply per wire mode, the request
    // recorded verbatim, and every call logged so a test can prove the bridge
    // was — or was never — reached.
    fn install_bridge(&self, replies: &[(&str, Value)]) {
        for (mode, reply) in replies {
            fs::write(
                self.root.join(format!("reply-{mode}.json")),
                serde_json::to_vec(reply).expect("encode the prepared bridge reply"),
            )
            .expect("write the prepared bridge reply");
        }
        let root = self.root.display();
        let script = format!(
            "#!/bin/sh\n\
             root='{root}'\n\
             request=\"$root/bridge-request.json\"\n\
             cat > \"$request\"\n\
             mode=`sed -n 's/.*\"mode\":\"\\([a-z]*\\)\".*/\\1/p' \"$request\"`\n\
             printf '%s\\n' \"$mode\" >> \"$root/bridge-calls\"\n\
             reply=\"$root/reply-$mode.json\"\n\
             if [ ! -f \"$reply\" ]; then\n\
             \tprintf 'no prepared reply for mode %s\\n' \"$mode\" >&2\n\
             \texit 1\n\
             fi\n\
             request_id=`sed -n 's/.*\"request_id\":\"\\([0-9a-zA-Z._-]*\\)\".*/\\1/p' \"$request\"`\n\
             sed \"s/{REPLY_REQUEST_ID}/$request_id/g\" \"$reply\"\n"
        );
        let path = self.root.join("weles-bridge.sh");
        fs::write(&path, script).expect("write the bridge stub");
        fs::set_permissions(&path, fs::Permissions::from_mode(octal("700")))
            .expect("make the bridge stub owner-executable");
        std::env::set_var(BRIDGE_ENV, &path);
    }

    fn bridge_calls(&self) -> Vec<String> {
        fs::read_to_string(self.root.join("bridge-calls"))
            .map(|text| text.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn bridge_request(&self) -> Value {
        let raw = fs::read_to_string(self.root.join("bridge-request.json"))
            .expect("the bridge recorded no request");
        serde_json::from_str(&raw).expect("the recorded bridge request is not JSON")
    }

    fn audit_ops(&self) -> Vec<String> {
        fs::read_to_string(self.root.join("audit.jsonl"))
            .map(|text| {
                text.lines()
                    .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    .map(|entry| text_of(&entry, "op"))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn assert_audited(&self, op: &str) {
        let ops = self.audit_ops();
        assert!(
            ops.iter().any(|found| found == op),
            "no {op} audit in {ops:?}"
        );
    }

    // Grants minted through the real command journal asynchronously; wait for
    // the entry so the worker cannot resurrect the lab directory after drop.
    fn mint(&self, consumer: &str, capabilities: &str) -> Result<String> {
        let flags = flag_map(&[("capabilities", capabilities)]);
        let minted = tokens::dispatch("token-mint", &flags, &[consumer.to_string()])?
            .and_then(|value| {
                value
                    .get("token")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .expect("token-mint returned no bearer token");
        let attempts = "300".parse::<u64>().expect("attempt budget");
        let pause = Duration::from_millis("10".parse().expect("poll interval"));
        for _ in u64::MIN..attempts {
            if self.audit_ops().iter().any(|op| op == "token-mint") {
                break;
            }
            std::thread::sleep(pause);
        }
        Ok(minted)
    }

    fn token_file(&self, name: &str, token: &str) -> String {
        let path = self.root.join(name);
        fs::write(&path, token).expect("write the bearer token file");
        fs::set_permissions(&path, fs::Permissions::from_mode(octal("600")))
            .expect("make the bearer token file owner-only");
        path.display().to_string()
    }

    // A live credential the Weles lifecycle already manages.
    fn managed_login(&self, id: &str, password: &str) {
        let mut fields = Map::new();
        fields.insert("username".to_string(), json!(ACCOUNT_UPN));
        fields.insert("password".to_string(), json!(password));
        let payload = schema::payload("login", fields, Map::new()).expect("build a login payload");
        self.vault()
            .set_managed_item(
                id,
                "login",
                &payload,
                &[],
                &["managed:weles".to_string()],
                ManagedWrite {
                    controller: "weles",
                    writer: CONSUMER,
                    operation_id: None,
                },
            )
            .expect("create the managed credential");
    }

    // A live managed credential whose canonical field is not the one any
    // provider contract writes: the shape a lifecycle must refuse rather than
    // remap.
    fn managed_field(&self, id: &str, field: &str, password: &str) {
        let mut fields = Map::new();
        fields.insert(field.to_string(), json!(password));
        let payload =
            schema::payload("stado-secret", fields, Map::new()).expect("build a secret payload");
        self.vault()
            .set_managed_item(
                id,
                "stado-secret",
                &payload,
                &[],
                &["managed:weles".to_string()],
                ManagedWrite {
                    controller: "weles",
                    writer: CONSUMER,
                    operation_id: None,
                },
            )
            .expect("create the managed credential");
    }

    // An item still on the pre-v2 envelope: no format marker and the
    // ciphertext directly under `current`, exactly what migrate-v2 reads.
    fn legacy_item(&self, id: &str, field: &str, password: &str) {
        let mut vault = self.vault();
        let fingerprint = vault
            .recipient_fpr(OWNER_UID)
            .expect("the lab owner fingerprint");
        let cipher = crypto::encrypt_to(&[fingerprint], &json!({field: password}).to_string())
            .expect("encrypt the legacy revision");
        vault
            .doc_mut()
            .get_mut("items")
            .and_then(Value::as_object_mut)
            .expect("the vault items section")
            .insert(
                id.to_string(),
                json!({
                    "type": "login",
                    "current": cipher,
                    "recipients": [OWNER_UID],
                    "written_by": OWNER_UID,
                    "tags": ["managed:weles"],
                }),
            );
        vault.save().expect("persist the legacy item");
    }

    fn owner_login(&self, id: &str, password: &str) {
        let mut fields = Map::new();
        fields.insert("username".to_string(), json!(ACCOUNT_UPN));
        fields.insert("password".to_string(), json!(password));
        let payload = schema::payload("login", fields, Map::new()).expect("build a login payload");
        self.vault()
            .set_item(id, "login", &payload, &[], &[])
            .expect("create the owner-controlled item");
    }

    fn seal(&self, id: &str) -> Value {
        accepted(self.credential(
            &["seal-directory", id],
            &[
                ("provider", IDENTITY_PROVIDER),
                ("tenant", TENANT_ID),
                ("object-id", OBJECT_ID),
                ("account-upn", ACCOUNT_UPN),
                ("local", "true"),
            ],
        ))
    }

    fn record(&self, id: &str) -> Value {
        let vault = self.vault();
        request_payload(
            vault
                .get_item(&request_item_id(id))
                .expect("read the operation record"),
        )
        .expect("decode the operation record")
    }

    fn save_record(&self, id: &str, record: &Value) {
        save_request(&self.vault_path, &request_item_id(id), record)
            .expect("persist the operation record");
    }

    // Freeze a credential the way the lifecycle does: one submit whose bridge
    // reply reports an unknown provider effect.
    fn quarantine(&self, id: &str) -> Value {
        self.install_bridge(&[(
            "submit",
            bridge_reply(
                "operation_completed",
                "acquire",
                GENERIC_PROVIDER,
                id,
                &[
                    ("providerEffect", json!("unknown")),
                    ("retryable", json!(true)),
                ],
            ),
        )]);
        let refused = self.credential(
            &["acquire", id],
            &[
                ("provider", GENERIC_PROVIDER),
                ("consumer", CONSUMER),
                ("local", "true"),
            ],
        );
        let value = accepted(refused);
        assert_eq!(text_of(&value, "status"), STATE_QUARANTINED);
        value
    }

    // The same freeze against a live managed credential, so the item itself
    // carries the frozen lifecycle block rather than only the record.
    fn quarantine_managed(&self, id: &str) -> Value {
        self.managed_login(id, "current-password");
        self.seal(id);
        self.install_bridge(&[(
            "submit",
            bridge_reply(
                "operation_completed",
                "rotate",
                IDENTITY_PROVIDER,
                id,
                &[("providerEffect", json!("unknown"))],
            ),
        )]);
        let frozen = accepted(self.credential(
            &["rotate", id],
            &[
                ("provider", IDENTITY_PROVIDER),
                ("consumer", CONSUMER),
                ("local", "true"),
            ],
        ));
        assert_eq!(text_of(&frozen, "status"), STATE_QUARANTINED);
        assert_eq!(
            context_block(&self.vault(), id, "lifecycle")
                .as_ref()
                .map(|block| text_of(block, "state")),
            Some(STATE_QUARANTINED.to_string())
        );
        frozen
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", &self.gnupg)
            .args(["--kill", "all"])
            .status();
        let _ = fs::remove_dir_all(&self.root);
        std::env::remove_var(BRIDGE_ENV);
    }
}

// One Weles reply in the camelCase envelope the bridge speaks.
fn bridge_reply(
    status: &str,
    operation: &str,
    provider: &str,
    credential_id: &str,
    extra: &[(&str, Value)],
) -> Value {
    let mut reply = Map::new();
    reply.insert("status".to_string(), json!(status));
    reply.insert("operation".to_string(), json!(operation));
    reply.insert("provider".to_string(), json!(provider));
    reply.insert("vaultItemId".to_string(), json!(credential_id));
    for (key, value) in extra {
        reply.insert((*key).to_string(), value.clone());
    }
    Value::Object(reply)
}

fn approval_object() -> Value {
    json!({
        "approval_id": "approval-1",
        "resume_token": "resume-token-1",
        "phase": "identity_verification",
        "provider_effect": "none",
        "expires_at": FUTURE_EXPIRY,
        "instruction": "Approve the sign-in on the registered device",
    })
}

// `request_id` is the placeholder the bridge stub substitutes in a prepared
// reply, or one exact 64-hex request id when the receipt is checked directly.
fn receipt_object(operation: &str, request_id: &str) -> Value {
    json!({
        "tenant_id": TENANT_ID,
        "principal_object_id": OBJECT_ID,
        "account_upn": ACCOUNT_UPN,
        "operation": operation,
        "request_id": request_id,
        "evidence_digest": EVIDENCE_DIGEST,
        "execution_host": "weles-runner-1",
        "changed_at": "2026-01-01T00:00:00Z",
        "verified_at": "2026-01-01T00:00:01Z",
        "action_log_id": ACTION_LOG_ID,
    })
}

// A persisted operation record of the shape `update_request` writes.
fn operation_record(
    version: &str,
    operation: &str,
    credential_id: &str,
    status: &str,
    directory: Option<Value>,
    weles: Option<Value>,
) -> Value {
    json!({
        "version": version,
        "mode": "submit",
        "action_log_id": Value::Null,
        "request_id": EVIDENCE_DIGEST,
        "operation": operation,
        "credential_id": credential_id,
        "provider": if directory.is_some() { IDENTITY_PROVIDER } else { GENERIC_PROVIDER },
        "consumer": CONSUMER,
        "purpose": CONSUMER,
        "account_email": Value::Null,
        "directory": directory,
        "baseline_revision": u64::MIN,
        "field": "password",
        "status": status,
        "created_at": "2026-01-01T00:00:00Z",
        "dry_run": false,
        "weles": weles,
    })
}

fn sealed_wire_block() -> Value {
    json!({
        "provider": IDENTITY_PROVIDER,
        "tenant_id": TENANT_ID,
        "principal_object_id": OBJECT_ID,
        "account_upn": ACCOUNT_UPN,
    })
}

// ---------------------------------------------------------------------------
// 1. Wire version
// ---------------------------------------------------------------------------

#[test]
fn start_operation_refuses_an_operation_record_from_an_older_wire_version() {
    for version in [WIRE_V1, WIRE_V2] {
        let lab = Lab::new();
        lab.install_bridge(&[(
            "submit",
            bridge_reply(
                "operation_queued",
                "acquire",
                GENERIC_PROVIDER,
                CREDENTIAL,
                &[("actionLogId", json!(ACTION_LOG_ID))],
            ),
        )]);
        lab.save_record(
            CREDENTIAL,
            &operation_record(version, "acquire", CREDENTIAL, "pending", None, None),
        );
        refusal(
            lab.credential(
                &["acquire", CREDENTIAL],
                &[
                    ("provider", GENERIC_PROVIDER),
                    ("consumer", CONSUMER),
                    ("local", "true"),
                ],
            ),
            "unsupported wire version",
        );
        assert!(
            lab.bridge_calls().is_empty(),
            "an unsupported wire version must never reach the bridge"
        );
    }
}

#[test]
fn status_refuses_an_operation_record_from_an_older_wire_version() {
    for version in [WIRE_V1, WIRE_V2] {
        let lab = Lab::new();
        lab.save_record(
            CREDENTIAL,
            &operation_record(version, "rotate", CREDENTIAL, "pending", None, None),
        );
        refusal(
            lab.credential(&["status", CREDENTIAL], &[("local", "true")]),
            "unsupported wire version",
        );
    }
}

#[test]
fn resume_refuses_an_operation_record_from_an_older_wire_version() {
    for version in [WIRE_V1, WIRE_V2] {
        let lab = Lab::new();
        lab.save_record(
            CREDENTIAL,
            &operation_record(
                version,
                "rotate",
                CREDENTIAL,
                "needs_human_approval",
                None,
                Some(json!({"approval": approval_object()})),
            ),
        );
        refusal(
            lab.credential(
                &["resume", CREDENTIAL],
                &[
                    ("approval", "approval-1"),
                    ("resume-token", "resume-token-1"),
                    ("local", "true"),
                ],
            ),
            "unsupported wire version",
        );
    }
}

#[test]
fn managed_write_authority_refuses_an_older_wire_version_record() {
    let lab = Lab::new();
    lab.managed_login(CREDENTIAL, "current-password");
    let baseline = item_revision(&lab.vault(), CREDENTIAL).expect("managed item revision");

    for version in [WIRE_V1, WIRE_V2, WIRE_V3] {
        let mut record = operation_record(version, "rotate", CREDENTIAL, "pending", None, None);
        record
            .as_object_mut()
            .expect("operation record object")
            .insert("baseline_revision".to_string(), json!(baseline));
        lab.save_record(CREDENTIAL, &record);
        let authorized = authorize_managed_write(
            &lab.vault(),
            CREDENTIAL,
            "password",
            CONSUMER,
            EVIDENCE_DIGEST,
            &["rotate"],
            baseline,
        );
        if version == WIRE_V3 {
            accepted(authorized);
        } else {
            refusal(
                authorized,
                "managed write does not match the active credential operation",
            );
        }
    }
}

#[test]
fn a_bridge_response_naming_another_wire_version_is_refused() {
    let accepted_reply = json!({
        "status": "operation_queued",
        "version": WIRE_V3,
        "actionLogId": ACTION_LOG_ID,
    });
    accepted(sanitized_response(&accepted_reply));

    for version in [WIRE_V1, WIRE_V2, "skarbiec.credential-operation.v4"] {
        let reply = json!({
            "status": "operation_queued",
            "version": version,
            "actionLogId": ACTION_LOG_ID,
        });
        refusal(sanitized_response(&reply), "wire version");
    }
}

// ---------------------------------------------------------------------------
// 2. The write-once directory contract
// ---------------------------------------------------------------------------

#[test]
fn seal_directory_writes_exactly_the_canonical_block_once() {
    let lab = Lab::new();
    let sealed = lab.seal(CREDENTIAL);

    let block = sealed.get("directory").expect("sealed directory block");
    assert_eq!(
        keys_of(block),
        vec![
            "account_upn".to_string(),
            "principal_object_id".to_string(),
            "provider".to_string(),
            "sealed_at".to_string(),
            "tenant_id".to_string(),
        ]
    );
    assert_eq!(text_of(block, "provider"), IDENTITY_PROVIDER);
    assert_eq!(text_of(block, "tenant_id"), TENANT_ID);
    assert_eq!(text_of(block, "principal_object_id"), OBJECT_ID);
    assert_eq!(text_of(block, "account_upn"), ACCOUNT_UPN);
    assert!(!text_of(block, "sealed_at").is_empty());

    let persisted = sealed_record(&lab.vault(), CREDENTIAL)
        .expect("read the sealed record")
        .expect("the sealed record exists");
    assert_eq!(
        checked_directory(&persisted).expect("canonical sealed record"),
        sealed_wire_block()
    );
    lab.assert_audited("credential-directory-sealed");
}

#[test]
fn sealing_a_second_directory_contract_is_refused() {
    let lab = Lab::new();
    lab.seal(CREDENTIAL);
    refusal(
        lab.credential(
            &["seal-directory", CREDENTIAL],
            &[
                ("provider", IDENTITY_PROVIDER),
                ("tenant", OTHER_TENANT_ID),
                ("object-id", OTHER_OBJECT_ID),
                ("account-upn", OTHER_ACCOUNT_UPN),
                ("local", "true"),
            ],
        ),
        "already carries a sealed directory contract",
    );
    let persisted = sealed_record(&lab.vault(), CREDENTIAL)
        .expect("read the sealed record")
        .expect("the sealed record survives the refusal");
    assert_eq!(text_of(&persisted, "tenant_id"), TENANT_ID);
}

#[test]
fn reseal_requires_a_reseal_capability() {
    let lab = Lab::new();
    lab.managed_login(CREDENTIAL, "current-password");
    lab.seal(CREDENTIAL);

    let admin_only = accepted(lab.mint("directory-admin", &format!("admin:{CREDENTIAL}")));
    let admin_file = lab.token_file("admin.token", &admin_only);
    let reseal_flags = |consumer: &str, token_file: &str| {
        vec![
            ("provider", IDENTITY_PROVIDER.to_string()),
            ("tenant", OTHER_TENANT_ID.to_string()),
            ("object-id", OTHER_OBJECT_ID.to_string()),
            ("account-upn", OTHER_ACCOUNT_UPN.to_string()),
            ("as", consumer.to_string()),
            ("token-file", token_file.to_string()),
            ("local", "true".to_string()),
        ]
    };
    let owned = reseal_flags("directory-admin", &admin_file);
    let borrowed: Vec<(&str, &str)> = owned
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    refusal(
        lab.credential(&["reseal", CREDENTIAL], &borrowed),
        "holds no reseal capability",
    );
    let unchanged = sealed_record(&lab.vault(), CREDENTIAL)
        .expect("read the sealed record")
        .expect("the sealed record survives the refusal");
    assert_eq!(text_of(&unchanged, "tenant_id"), TENANT_ID);

    let sealer = accepted(lab.mint("directory-sealer", &format!("reseal:{CREDENTIAL}")));
    let sealer_file = lab.token_file("reseal.token", &sealer);
    let owned = reseal_flags("directory-sealer", &sealer_file);
    let borrowed: Vec<(&str, &str)> = owned
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    let resealed = accepted(lab.credential(&["reseal", CREDENTIAL], &borrowed));
    assert_eq!(resealed.get("resealed"), Some(&json!(true)));
    let rewritten = sealed_record(&lab.vault(), CREDENTIAL)
        .expect("read the sealed record")
        .expect("the resealed record exists");
    assert_eq!(text_of(&rewritten, "tenant_id"), OTHER_TENANT_ID);
    lab.assert_audited("credential-directory-resealed");
}

#[test]
fn the_wire_directory_block_carries_exactly_four_keys_without_sealed_at() {
    let lab = Lab::new();
    let sealed = lab.seal(CREDENTIAL);
    let block = sealed.get("directory").expect("sealed directory block");

    let on_wire = wire_directory(block).expect("build the wire directory block");
    assert_eq!(on_wire, sealed_wire_block());
    assert!(on_wire.get("sealed_at").is_none());

    // The same block, as the bridge actually receives it.
    lab.install_bridge(&[(
        "submit",
        bridge_reply(
            "operation_plan",
            "verify",
            IDENTITY_PROVIDER,
            CREDENTIAL,
            &[],
        ),
    )]);
    accepted(lab.credential(
        &["verify", CREDENTIAL],
        &[
            ("provider", IDENTITY_PROVIDER),
            ("consumer", CONSUMER),
            ("dry-run", "true"),
            ("local", "true"),
        ],
    ));
    let submitted = lab.bridge_request();
    let submitted_block = submitted.get("directory").expect("wire directory block");
    assert_eq!(
        keys_of(submitted_block),
        vec![
            "account_upn".to_string(),
            "principal_object_id".to_string(),
            "provider".to_string(),
            "tenant_id".to_string(),
        ]
    );
}

// ---------------------------------------------------------------------------
// 3. `--expect-*` is a cross-check, refused before anything is submitted
// ---------------------------------------------------------------------------

#[test]
fn a_mismatched_expectation_refuses_before_the_bridge_runs() {
    for (flag, wrong) in [
        ("expect-tenant", OTHER_TENANT_ID),
        ("expect-object-id", OTHER_OBJECT_ID),
        ("expect-upn", OTHER_ACCOUNT_UPN),
    ] {
        let lab = Lab::new();
        lab.seal(CREDENTIAL);
        lab.install_bridge(&[(
            "submit",
            bridge_reply(
                "operation_plan",
                "verify",
                IDENTITY_PROVIDER,
                CREDENTIAL,
                &[],
            ),
        )]);
        refusal(
            lab.credential(
                &["verify", CREDENTIAL],
                &[
                    ("provider", IDENTITY_PROVIDER),
                    ("consumer", CONSUMER),
                    ("dry-run", "true"),
                    ("local", "true"),
                    (flag, wrong),
                ],
            ),
            EXPECTATION_MISMATCH,
        );
        assert!(
            lab.bridge_calls().is_empty(),
            "{flag} mismatch reached the bridge before refusing"
        );
    }
}

#[test]
fn matching_expectations_do_not_block_the_operation() {
    let lab = Lab::new();
    lab.seal(CREDENTIAL);
    lab.install_bridge(&[(
        "submit",
        bridge_reply(
            "operation_plan",
            "verify",
            IDENTITY_PROVIDER,
            CREDENTIAL,
            &[],
        ),
    )]);
    let planned = accepted(lab.credential(
        &["verify", CREDENTIAL],
        &[
            ("provider", IDENTITY_PROVIDER),
            ("consumer", CONSUMER),
            ("dry-run", "true"),
            ("local", "true"),
            ("expect-tenant", TENANT_ID),
            ("expect-object-id", OBJECT_ID),
            ("expect-upn", ACCOUNT_UPN),
        ],
    ));
    assert_eq!(planned.get("ok"), Some(&json!(true)));
    assert_eq!(lab.bridge_calls(), vec!["submit".to_string()]);
}

// ---------------------------------------------------------------------------
// 4. provider_effect
// ---------------------------------------------------------------------------

#[test]
fn provider_effect_none_allows_a_retry() {
    // Nothing changed at the provider, so there is nothing to roll back and
    // nothing standing between the operator and another attempt.
    for rollback in [json!("none"), json!("completed"), Value::Null] {
        let existing = operation_record(
            WIRE_V3,
            "rotate",
            CREDENTIAL,
            "operation_failed",
            None,
            Some(json!({"provider_effect": "none", "rollback_status": rollback})),
        );
        for operation in ["rotate", "verify", "reset", "remove"] {
            accepted(enforce_retry_barrier(&existing, CREDENTIAL, operation));
        }
    }
}

#[test]
fn provider_effect_changed_blocks_the_same_operation_and_admits_verify() {
    let existing = operation_record(
        WIRE_V3,
        "rotate",
        CREDENTIAL,
        "operation_failed",
        None,
        Some(json!({"provider_effect": "changed", "rollback_status": "none"})),
    );
    for operation in ["rotate", "reset", "remove", "acquire"] {
        refusal(
            enforce_retry_barrier(&existing, CREDENTIAL, operation),
            "PROVIDER_EFFECT_CHANGED_RETRY_BLOCKED",
        );
    }
    accepted(enforce_retry_barrier(&existing, CREDENTIAL, "verify"));

    // A confirmed rollback settles the question and lifts the barrier.
    let rolled_back = operation_record(
        WIRE_V3,
        "rotate",
        CREDENTIAL,
        "operation_failed",
        None,
        Some(json!({"provider_effect": "changed", "rollback_status": "completed"})),
    );
    accepted(enforce_retry_barrier(&rolled_back, CREDENTIAL, "rotate"));
}

#[test]
fn provider_effect_unknown_quarantines_and_is_never_retryable() {
    let lab = Lab::new();
    let frozen = lab.quarantine(CREDENTIAL);

    // The bridge insisted the failure was retryable; Skarbiec froze it anyway.
    assert_eq!(
        frozen.get("weles").and_then(|weles| weles.get("retryable")),
        Some(&json!(true))
    );
    assert_eq!(frozen.get("ok"), Some(&json!(false)));
    assert_eq!(
        lifecycle_state(&lab.vault(), CREDENTIAL).expect("lifecycle state"),
        STATE_QUARANTINED
    );
    lab.assert_audited("credential-operation-quarantined");

    refusal(
        enforce_retry_barrier(&lab.record(CREDENTIAL), CREDENTIAL, "acquire"),
        "unknown state",
    );
    refusal(
        lab.credential(
            &["acquire", CREDENTIAL],
            &[
                ("provider", GENERIC_PROVIDER),
                ("consumer", CONSUMER),
                ("local", "true"),
            ],
        ),
        "is quarantined",
    );
    let reported = accepted(lab.credential(&["status", CREDENTIAL], &[("local", "true")]));
    assert_eq!(text_of(&reported, "status"), STATE_QUARANTINED);
    assert_eq!(reported.get("ok"), Some(&json!(false)));
    assert_eq!(
        lab.bridge_calls(),
        vec!["submit".to_string()],
        "a quarantined credential must never be polled again"
    );
}

#[test]
fn an_unknown_provider_effect_value_is_refused() {
    for effect in ["rotated", "", "NONE", "unknown "] {
        let reply = json!({
            "status": "operation_completed",
            "providerEffect": effect,
        });
        refusal(sanitized_response(&reply), "providerEffect");
    }
    for effect in ["none", "changed", "unknown"] {
        let reply = json!({"status": "operation_completed", "providerEffect": effect});
        let sanitized = accepted(sanitized_response(&reply));
        assert_eq!(text_of(&sanitized, "provider_effect"), effect);
    }
}

#[test]
fn an_unproven_rollback_freezes_the_credential() {
    let lab = Lab::new();
    let unresolved = [
        json!({"status": "operation_failed", "provider_effect": "changed", "rollback_status": "none"}),
        json!({"status": "operation_completed", "rollback_status": "failed"}),
        json!({"status": "operation_completed", "rollback_status": "unknown"}),
        json!({"status": "operation_completed", "provider_effect": "unknown"}),
    ];
    for response in unresolved {
        assert!(
            enforce_provider_effect(
                &lab.vault_path,
                CREDENTIAL,
                "rotate",
                EVIDENCE_DIGEST,
                &response,
            )
            .expect("evaluate the provider effect"),
            "{response} should have frozen the credential"
        );
    }
    let settled = [
        json!({"status": "operation_completed", "provider_effect": "changed", "rollback_status": "completed"}),
        json!({"status": "operation_failed", "provider_effect": "changed", "rollback_status": "completed"}),
        json!({"status": "operation_completed", "provider_effect": "none"}),
    ];
    for response in settled {
        assert!(
            !enforce_provider_effect(
                &lab.vault_path,
                CREDENTIAL,
                "rotate",
                EVIDENCE_DIGEST,
                &response,
            )
            .expect("evaluate the provider effect"),
            "{response} should not have frozen the credential"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. quarantine
// ---------------------------------------------------------------------------

#[test]
fn a_quarantined_credential_refuses_every_operation() {
    let lab = Lab::new();
    lab.quarantine(CREDENTIAL);
    let calls_after_freeze = lab.bridge_calls().len();

    for operation in ["acquire", "rotate", "reset", "verify", "remove", "adopt"] {
        refusal(
            lab.credential(
                &[operation, CREDENTIAL],
                &[
                    ("provider", GENERIC_PROVIDER),
                    ("consumer", CONSUMER),
                    (
                        "password-stdin",
                        if operation == "adopt" {
                            "true"
                        } else {
                            "false"
                        },
                    ),
                    ("local", "true"),
                ],
            ),
            "is quarantined",
        );
    }
    refusal(
        lab.credential(
            &["seal-directory", CREDENTIAL],
            &[
                ("provider", IDENTITY_PROVIDER),
                ("tenant", TENANT_ID),
                ("object-id", OBJECT_ID),
                ("account-upn", ACCOUNT_UPN),
                ("local", "true"),
            ],
        ),
        "is quarantined",
    );
    refusal(
        lab.credential(
            &["reseal", CREDENTIAL],
            &[
                ("provider", IDENTITY_PROVIDER),
                ("tenant", TENANT_ID),
                ("object-id", OBJECT_ID),
                ("account-upn", ACCOUNT_UPN),
                ("local", "true"),
            ],
        ),
        "is quarantined",
    );
    refusal(
        lab.credential(
            &["resume", CREDENTIAL],
            &[
                ("approval", "approval-1"),
                ("resume-token", "resume-token-1"),
                ("local", "true"),
            ],
        ),
        "is quarantined",
    );
    assert_eq!(
        lab.bridge_calls().len(),
        calls_after_freeze,
        "a frozen credential must never reach the bridge again"
    );
}

#[test]
fn resolve_quarantine_requires_the_exact_confirmation_phrase() {
    let lab = Lab::new();
    lab.quarantine(CREDENTIAL);
    let admin = accepted(lab.mint(
        "quarantine-admin",
        &format!("admin:{}", request_item_id(CREDENTIAL)),
    ));
    let token_file = lab.token_file("admin.token", &admin);

    let mut wrong = QUARANTINE_CONFIRMATION.to_string();
    wrong.push('.');
    for phrase in [
        "",
        "i know which password this provider account accepts",
        wrong.as_str(),
    ] {
        refusal(
            lab.credential(
                &["resolve-quarantine", CREDENTIAL],
                &[
                    ("confirm", phrase),
                    ("as", "quarantine-admin"),
                    ("token-file", token_file.as_str()),
                    ("local", "true"),
                ],
            ),
            "usage: credential resolve-quarantine",
        );
    }
    assert_eq!(
        lifecycle_state(&lab.vault(), CREDENTIAL).expect("lifecycle state"),
        STATE_QUARANTINED
    );
}

#[test]
fn resolve_quarantine_requires_an_admin_capability() {
    let lab = Lab::new();
    lab.quarantine(CREDENTIAL);
    let weak = accepted(lab.mint(
        "quarantine-watcher",
        &format!("sync:{}", request_item_id(CREDENTIAL)),
    ));
    let token_file = lab.token_file("weak.token", &weak);
    refusal(
        lab.credential(
            &["resolve-quarantine", CREDENTIAL],
            &[
                ("confirm", QUARANTINE_CONFIRMATION),
                ("as", "quarantine-watcher"),
                ("token-file", token_file.as_str()),
                ("local", "true"),
            ],
        ),
        "holds no admin capability",
    );
    assert_eq!(
        lifecycle_state(&lab.vault(), CREDENTIAL).expect("lifecycle state"),
        STATE_QUARANTINED
    );
}

#[test]
fn resolve_quarantine_returns_the_credential_to_unmanaged_and_audits_it() {
    let lab = Lab::new();
    lab.quarantine_managed(CREDENTIAL);
    let admin = accepted(lab.mint("quarantine-admin", &format!("admin:{CREDENTIAL}")));
    let token_file = lab.token_file("admin.token", &admin);
    let resolved = accepted(lab.credential(
        &["resolve-quarantine", CREDENTIAL],
        &[
            ("confirm", QUARANTINE_CONFIRMATION),
            ("as", "quarantine-admin"),
            ("token-file", token_file.as_str()),
            ("local", "true"),
        ],
    ));
    assert_eq!(text_of(&resolved, "status"), STATE_UNMANAGED);

    // Knowing the password again is an explicit act: the item itself records
    // that it left quarantine, and it lands in unmanaged, not managed.
    let lifecycle = context_block(&lab.vault(), CREDENTIAL, "lifecycle")
        .expect("the resolved item carries a lifecycle block");
    assert_eq!(text_of(&lifecycle, "state"), STATE_UNMANAGED);
    assert_eq!(text_of(&lifecycle, "operation"), "resolve-quarantine");
    assert_eq!(
        lifecycle_state(&lab.vault(), CREDENTIAL).expect("lifecycle state"),
        STATE_UNMANAGED
    );
    let quarantine = context_block(&lab.vault(), CREDENTIAL, "quarantine")
        .expect("the resolved item keeps its quarantine record");
    assert_eq!(text_of(&quarantine, "state"), "resolved");
    assert_eq!(text_of(&quarantine, "resolved_by"), "quarantine-admin");
    assert_eq!(
        text_of(&lab.record(CREDENTIAL), "status"),
        "quarantine_resolved"
    );
    lab.assert_audited("credential-quarantine-resolved");
}

// ---------------------------------------------------------------------------
// 6. approval: six fields or no resource at all
// ---------------------------------------------------------------------------

#[test]
fn human_approval_without_an_approval_resource_is_refused() {
    let reply = json!({"status": "needs_human_approval"});
    refusal(
        sanitized_response(&reply),
        "asked for human approval without an approval resource",
    );

    let lab = Lab::new();
    lab.install_bridge(&[(
        "submit",
        bridge_reply(
            "needs_human_approval",
            "acquire",
            GENERIC_PROVIDER,
            CREDENTIAL,
            &[("actionLogId", json!(ACTION_LOG_ID))],
        ),
    )]);
    refusal(
        lab.credential(
            &["acquire", CREDENTIAL],
            &[
                ("provider", GENERIC_PROVIDER),
                ("consumer", CONSUMER),
                ("local", "true"),
            ],
        ),
        "without an approval resource",
    );
    assert_eq!(text_of(&lab.record(CREDENTIAL), "status"), "failed");
}

#[test]
fn an_approval_missing_or_malformed_in_any_one_field_is_refused() {
    accepted(checked_approval(&json!({"approval": approval_object()})));

    let corruptions = [
        ("approval_id", json!("")),
        ("resume_token", json!("token with spaces")),
        ("phase", json!("teleportation")),
        ("provider_effect", json!("rotated")),
        ("expires_at", json!("tomorrow")),
        ("instruction", json!("")),
    ];
    for (field, broken) in corruptions {
        let mut approval = approval_object();
        approval
            .as_object_mut()
            .expect("approval object")
            .insert(field.to_string(), broken);
        refusal(checked_approval(&json!({"approval": approval})), field);

        let mut missing = approval_object();
        missing
            .as_object_mut()
            .expect("approval object")
            .remove(field);
        refusal(checked_approval(&json!({"approval": missing})), field);
    }
}

#[test]
fn an_expired_approval_releases_the_operation_and_its_lock() {
    let lab = Lab::new();
    let mut expired = approval_object();
    expired
        .as_object_mut()
        .expect("approval object")
        .insert("expires_at".to_string(), json!(PAST_EXPIRY));
    lab.install_bridge(&[(
        "submit",
        bridge_reply(
            "needs_human_approval",
            "acquire",
            GENERIC_PROVIDER,
            CREDENTIAL,
            &[("actionLogId", json!(ACTION_LOG_ID)), ("approval", expired)],
        ),
    )]);
    let waiting = accepted(lab.credential(
        &["acquire", CREDENTIAL],
        &[
            ("provider", GENERIC_PROVIDER),
            ("consumer", CONSUMER),
            ("local", "true"),
        ],
    ));
    assert_eq!(text_of(&waiting, "status"), "needs_human_approval");
    let first_request_id = text_of(&waiting, "request_id");

    refusal(
        lab.credential(
            &["resume", CREDENTIAL],
            &[
                ("approval", "approval-1"),
                ("resume-token", "resume-token-1"),
                ("local", "true"),
            ],
        ),
        "APPROVAL_EXPIRED",
    );
    assert_eq!(
        lab.bridge_calls(),
        vec!["submit".to_string()],
        "an expired approval must never be resumed against the provider"
    );
    assert_eq!(
        text_of(&lab.record(CREDENTIAL), "status"),
        "approval_expired"
    );
    assert!(
        !lab.lock_path().exists(),
        "the credential operation lock outlived the released operation"
    );
    lab.assert_audited("credential-approval-expired");

    // The released operation no longer blocks: a fresh submit is the way on.
    let resubmitted = accepted(lab.credential(
        &["acquire", CREDENTIAL],
        &[
            ("provider", GENERIC_PROVIDER),
            ("consumer", CONSUMER),
            ("local", "true"),
        ],
    ));
    assert_ne!(text_of(&resubmitted, "request_id"), first_request_id);
}

#[test]
fn resume_refuses_a_mismatched_approval_id_or_resume_token() {
    let lab = Lab::new();
    lab.install_bridge(&[(
        "submit",
        bridge_reply(
            "needs_human_approval",
            "acquire",
            GENERIC_PROVIDER,
            CREDENTIAL,
            &[
                ("actionLogId", json!(ACTION_LOG_ID)),
                ("approval", approval_object()),
            ],
        ),
    )]);
    accepted(lab.credential(
        &["acquire", CREDENTIAL],
        &[
            ("provider", GENERIC_PROVIDER),
            ("consumer", CONSUMER),
            ("local", "true"),
        ],
    ));

    for (approval_id, resume_token) in [
        ("approval-2", "resume-token-1"),
        ("approval-1", "resume-token-2"),
        ("approval-2", "resume-token-2"),
    ] {
        refusal(
            lab.credential(
                &["resume", CREDENTIAL],
                &[
                    ("approval", approval_id),
                    ("resume-token", resume_token),
                    ("local", "true"),
                ],
            ),
            "the presented approval does not match",
        );
    }
    assert_eq!(
        lab.bridge_calls(),
        vec!["submit".to_string()],
        "a mismatched approval must never reach the bridge"
    );
    assert_eq!(
        text_of(&lab.record(CREDENTIAL), "status"),
        "needs_human_approval"
    );
    assert!(!approval_expired(FUTURE_EXPIRY).expect("read the approval window"));
    assert!(approval_expired(PAST_EXPIRY).expect("read the approval window"));
}

// ---------------------------------------------------------------------------
// 7. receipt: ten fields, and the same principal as the sealed contract
// ---------------------------------------------------------------------------

#[test]
fn a_completed_directory_operation_without_a_receipt_quarantines_instead_of_committing() {
    let lab = Lab::new();
    lab.managed_login(CREDENTIAL, "current-password");
    lab.seal(CREDENTIAL);
    lab.install_bridge(&[
        (
            "submit",
            bridge_reply(
                "operation_queued",
                "rotate",
                IDENTITY_PROVIDER,
                CREDENTIAL,
                &[("actionLogId", json!(ACTION_LOG_ID))],
            ),
        ),
        (
            "status",
            bridge_reply(
                "operation_completed",
                "rotate",
                IDENTITY_PROVIDER,
                CREDENTIAL,
                &[("actionLogId", json!(ACTION_LOG_ID))],
            ),
        ),
    ]);
    let submitted = accepted(lab.credential(
        &["rotate", CREDENTIAL],
        &[
            ("provider", IDENTITY_PROVIDER),
            ("consumer", CONSUMER),
            ("local", "true"),
        ],
    ));
    // The provider value Weles staged is the one a receipt-less completion
    // must not be allowed to commit.
    let request_id = text_of(&submitted, "request_id");
    let baseline = item_revision(&lab.vault(), CREDENTIAL).expect("managed item revision");
    accepted(lab.vault().stage_managed_field(
        CREDENTIAL,
        "password",
        json!("provider-issued-password"),
        baseline,
        ManagedWrite {
            controller: "weles",
            writer: CONSUMER,
            operation_id: Some(&request_id),
        },
    ));

    let polled = accepted(lab.credential(&["status", CREDENTIAL], &[("local", "true")]));
    assert_eq!(text_of(&polled, "status"), STATE_QUARANTINED);
    assert_eq!(polled.get("ok"), Some(&json!(false)));
    assert_eq!(
        lifecycle_state(&lab.vault(), CREDENTIAL).expect("lifecycle state"),
        STATE_QUARANTINED
    );
    assert_eq!(
        item_revision(&lab.vault(), CREDENTIAL),
        Some(baseline),
        "a receipt-less completion must not commit a new revision"
    );
    let payload = lab
        .vault()
        .get_item(CREDENTIAL)
        .expect("read the frozen credential");
    assert_eq!(
        schema::field(&payload, "password").expect("password field"),
        &json!("current-password"),
        "a receipt-less completion committed the staged provider value"
    );
    assert!(pending_matches_request(
        &lab.vault(),
        CREDENTIAL,
        &request_id,
        "password",
        CONSUMER
    ));
    assert!(context_block(&lab.vault(), CREDENTIAL, "receipt").is_none());
    lab.assert_audited("credential-operation-quarantined");
}

#[test]
fn a_receipt_naming_another_principal_request_or_operation_is_refused() {
    let directory = sealed_wire_block();
    let receipt = json!({
        "tenant_id": TENANT_ID,
        "principal_object_id": OBJECT_ID,
        "account_upn": ACCOUNT_UPN,
        "operation": "rotate",
        "request_id": EVIDENCE_DIGEST,
    });
    assert!(receipt_matches(
        &receipt,
        Some(&directory),
        "rotate",
        EVIDENCE_DIGEST
    ));
    for (field, wrong) in [
        ("tenant_id", OTHER_TENANT_ID),
        ("principal_object_id", OTHER_OBJECT_ID),
        ("account_upn", OTHER_ACCOUNT_UPN),
    ] {
        let mut wrong_receipt = receipt.clone();
        wrong_receipt
            .as_object_mut()
            .expect("receipt object")
            .insert(field.to_string(), json!(wrong));
        assert!(
            !receipt_matches(&wrong_receipt, Some(&directory), "rotate", EVIDENCE_DIGEST),
            "a receipt naming another {field} was accepted"
        );
    }
    assert!(!receipt_matches(
        &receipt,
        Some(&directory),
        "reset",
        EVIDENCE_DIGEST
    ));
    assert!(!receipt_matches(
        &receipt,
        Some(&directory),
        "rotate",
        "another-request"
    ));

    // And the same refusal on the wire, where it actually protects a commit.
    let lab = Lab::new();
    lab.managed_login(CREDENTIAL, "current-password");
    lab.seal(CREDENTIAL);
    let mut foreign = receipt_object("rotate", REPLY_REQUEST_ID);
    foreign
        .as_object_mut()
        .expect("receipt object")
        .insert("principal_object_id".to_string(), json!(OTHER_OBJECT_ID));
    lab.install_bridge(&[
        (
            "submit",
            bridge_reply(
                "operation_queued",
                "rotate",
                IDENTITY_PROVIDER,
                CREDENTIAL,
                &[("actionLogId", json!(ACTION_LOG_ID))],
            ),
        ),
        (
            "status",
            bridge_reply(
                "operation_completed",
                "rotate",
                IDENTITY_PROVIDER,
                CREDENTIAL,
                &[("actionLogId", json!(ACTION_LOG_ID)), ("receipt", foreign)],
            ),
        ),
    ]);
    accepted(lab.credential(
        &["rotate", CREDENTIAL],
        &[
            ("provider", IDENTITY_PROVIDER),
            ("consumer", CONSUMER),
            ("local", "true"),
        ],
    ));
    refusal(
        lab.credential(&["status", CREDENTIAL], &[("local", "true")]),
        "names another principal, request, or operation",
    );
    assert!(context_block(&lab.vault(), CREDENTIAL, "receipt").is_none());
}

#[test]
fn receipt_request_id_and_evidence_digest_must_be_sixty_four_hexadecimal_characters() {
    accepted(checked_receipt(
        &json!({"receipt": receipt_object("rotate", SAMPLE_REQUEST_ID)}),
    ));
    let short_digest = "abc123";
    let long_digest = format!("{EVIDENCE_DIGEST}00");
    let non_hex = "z".repeat(EVIDENCE_DIGEST.len());
    for field in ["request_id", "evidence_digest"] {
        for wrong in [short_digest, long_digest.as_str(), non_hex.as_str()] {
            let mut receipt = receipt_object("rotate", SAMPLE_REQUEST_ID);
            receipt
                .as_object_mut()
                .expect("receipt object")
                .insert(field.to_string(), json!(wrong));
            refusal(
                checked_receipt(&json!({"receipt": receipt})),
                "64 hexadecimal characters",
            );
        }
    }
}

#[test]
fn a_receipt_requires_verified_at_and_allows_a_null_changed_at() {
    let mut nulled = receipt_object("rotate", SAMPLE_REQUEST_ID);
    nulled
        .as_object_mut()
        .expect("receipt object")
        .insert("changed_at".to_string(), Value::Null);
    let accepted_receipt = accepted(checked_receipt(&json!({"receipt": nulled})))
        .expect("a null changed_at is a complete receipt");
    assert_eq!(accepted_receipt.get("changed_at"), Some(&Value::Null));

    for field in [
        "tenant_id",
        "principal_object_id",
        "account_upn",
        "operation",
        "request_id",
        "evidence_digest",
        "execution_host",
        "changed_at",
        "verified_at",
        "action_log_id",
    ] {
        let mut receipt = receipt_object("rotate", SAMPLE_REQUEST_ID);
        receipt
            .as_object_mut()
            .expect("receipt object")
            .remove(field);
        refusal(checked_receipt(&json!({"receipt": receipt})), "receipt");
    }
    let mut null_verified = receipt_object("rotate", SAMPLE_REQUEST_ID);
    null_verified
        .as_object_mut()
        .expect("receipt object")
        .insert("verified_at".to_string(), Value::Null);
    refusal(
        checked_receipt(&json!({"receipt": null_verified})),
        "verified_at",
    );
}

#[test]
fn a_valid_receipt_is_persisted_in_context_and_returned_by_status() {
    let lab = Lab::new();
    lab.managed_login(CREDENTIAL, "current-password");
    lab.seal(CREDENTIAL);
    lab.install_bridge(&[
        (
            "submit",
            bridge_reply(
                "operation_queued",
                "rotate",
                IDENTITY_PROVIDER,
                CREDENTIAL,
                &[("actionLogId", json!(ACTION_LOG_ID))],
            ),
        ),
        (
            "status",
            bridge_reply(
                "operation_completed",
                "rotate",
                IDENTITY_PROVIDER,
                CREDENTIAL,
                &[
                    ("actionLogId", json!(ACTION_LOG_ID)),
                    ("providerEffect", json!("changed")),
                    ("rollbackStatus", json!("none")),
                    ("receipt", receipt_object("rotate", REPLY_REQUEST_ID)),
                ],
            ),
        ),
    ]);
    let submitted = accepted(lab.credential(
        &["rotate", CREDENTIAL],
        &[
            ("provider", IDENTITY_PROVIDER),
            ("consumer", CONSUMER),
            ("local", "true"),
        ],
    ));
    let request_id = text_of(&submitted, "request_id");
    let baseline = item_revision(&lab.vault(), CREDENTIAL).expect("managed item revision");

    // The managed write Weles performs once the operation is authorized.
    accepted(authorize_managed_write(
        &lab.vault(),
        CREDENTIAL,
        "password",
        CONSUMER,
        &request_id,
        &["rotate"],
        baseline,
    ));
    accepted(lab.vault().stage_managed_field(
        CREDENTIAL,
        "password",
        json!("provider-issued-password"),
        baseline,
        ManagedWrite {
            controller: "weles",
            writer: CONSUMER,
            operation_id: Some(&request_id),
        },
    ));

    let completed = accepted(lab.credential(&["status", CREDENTIAL], &[("local", "true")]));
    assert_eq!(text_of(&completed, "status"), "completed");
    assert_eq!(completed.get("ok"), Some(&json!(true)));
    assert_eq!(completed.get("externally_verified"), Some(&json!(true)));
    assert_eq!(
        text_of(&completed, "lifecycle_state"),
        STATE_MANAGED.to_string()
    );

    let emitted = completed.get("receipt").expect("status emits the receipt");
    assert_eq!(text_of(emitted, "request_id"), request_id);
    assert_eq!(text_of(emitted, "principal_object_id"), OBJECT_ID);
    assert_eq!(text_of(emitted, "evidence_digest"), EVIDENCE_DIGEST);
    let persisted =
        context_block(&lab.vault(), CREDENTIAL, "receipt").expect("the receipt is persisted");
    assert_eq!(&persisted, emitted);

    let payload = lab
        .vault()
        .get_item(CREDENTIAL)
        .expect("read the committed credential");
    assert_eq!(
        schema::field(&payload, "password").expect("password field"),
        &json!("provider-issued-password")
    );
    lab.assert_audited("credential-operation-completed");
}

// ---------------------------------------------------------------------------
// 8. adopt
// ---------------------------------------------------------------------------

#[test]
fn adopt_is_refused_without_local() {
    let lab = Lab::new();
    refusal(
        lab.credential(
            &["adopt", CREDENTIAL],
            &[
                ("provider", IDENTITY_PROVIDER),
                ("consumer", CONSUMER),
                ("password-stdin", "true"),
            ],
        ),
        "runs against the vault file it owns",
    );
    for subcommand in ["seal-directory", "reseal", "resolve-quarantine"] {
        refusal(
            lab.credential(&[subcommand, CREDENTIAL], &[]),
            "runs against the vault file it owns",
        );
    }
}

#[test]
fn adopt_is_refused_on_a_managed_credential() {
    let lab = Lab::new();
    lab.managed_login(CREDENTIAL, "current-password");
    lab.seal(CREDENTIAL);
    refusal(
        lab.credential(
            &["adopt", CREDENTIAL],
            &[
                ("provider", IDENTITY_PROVIDER),
                ("consumer", CONSUMER),
                ("password-stdin", "true"),
                ("local", "true"),
            ],
        ),
        "already a managed credential",
    );
    refusal(
        lab.credential(
            &["adopt", CREDENTIAL],
            &[
                ("provider", IDENTITY_PROVIDER),
                ("consumer", CONSUMER),
                ("local", "true"),
            ],
        ),
        "requires --password-stdin",
    );
}

#[test]
fn adopt_creates_the_missing_item_in_the_adopting_state_and_never_reports_it_verified() {
    let lab = Lab::new();
    lab.seal(CREDENTIAL);
    let directory = sealed_wire_block();
    let staging = AdoptStaging {
        shape: AdoptShape::Created,
        credential_id: CREDENTIAL,
        field: "password",
        consumer: CONSUMER,
        request_id: EVIDENCE_DIGEST,
        account: None,
        directory: Some(&directory),
    };
    let revision = accepted(stage_adopted_candidate(
        &lab.vault_path,
        &staging,
        "operator-supplied-password",
    ));
    assert_eq!(revision, one());
    assert_eq!(
        lifecycle_state(&lab.vault(), CREDENTIAL).expect("lifecycle state"),
        STATE_ADOPTING
    );

    let reported = accepted(status_once(&lab.vault_path, &[CREDENTIAL.to_string()]));
    assert_eq!(text_of(&reported, "status"), STATE_ADOPTING);
    assert_eq!(text_of(&reported, "lifecycle_state"), STATE_ADOPTING);
    assert_eq!(reported.get("externally_verified"), Some(&json!(false)));
    assert_eq!(reported.get("ok"), Some(&json!(false)));
}

#[test]
fn only_the_item_this_adopt_created_may_be_rolled_back() {
    let lab = Lab::new();
    lab.seal(CREDENTIAL);
    let directory = sealed_wire_block();

    // An item that existed before this request is never trashed by it.
    let preexisting = "preexisting-login";
    lab.managed_login(preexisting, "operator-password");
    refusal(
        trash_adopted_item(&mut lab.vault(), preexisting, EVIDENCE_DIGEST, CONSUMER),
        "not the item this adopt request created",
    );
    assert!(lab.vault().get_item(preexisting).is_ok());

    let staging = AdoptStaging {
        shape: AdoptShape::Created,
        credential_id: CREDENTIAL,
        field: "password",
        consumer: CONSUMER,
        request_id: EVIDENCE_DIGEST,
        account: None,
        directory: Some(&directory),
    };
    accepted(stage_adopted_candidate(
        &lab.vault_path,
        &staging,
        "operator-supplied-password",
    ));

    // Not even for the created item, if another request claims it.
    refusal(
        trash_adopted_item(&mut lab.vault(), CREDENTIAL, "another-request", CONSUMER),
        "not the item this adopt request created",
    );
    assert!(lab.vault().get_item(CREDENTIAL).is_ok());

    accepted(trash_adopted_item(
        &mut lab.vault(),
        CREDENTIAL,
        EVIDENCE_DIGEST,
        CONSUMER,
    ));
    assert!(lab.vault().get_item(CREDENTIAL).is_err());
    assert!(lab.vault().get_item(preexisting).is_ok());
    lab.assert_audited("credential-adopt-rolled-back");
}

#[test]
fn an_unconfirmed_adopt_candidate_is_unreadable_outside_the_verification_path() {
    let lab = Lab::new();
    lab.seal(CREDENTIAL);
    let directory = sealed_wire_block();
    let staging = AdoptStaging {
        shape: AdoptShape::Created,
        credential_id: CREDENTIAL,
        field: "password",
        consumer: CONSUMER,
        request_id: EVIDENCE_DIGEST,
        account: None,
        directory: Some(&directory),
    };
    accepted(stage_adopted_candidate(
        &lab.vault_path,
        &staging,
        "operator-supplied-password",
    ));

    // No active adopt request: the candidate is nobody's to read.
    assert!(candidate_hidden(
        &lab.vault(),
        CREDENTIAL,
        "password",
        CONSUMER
    ));
    assert!(matches!(
        managed_read(&lab.vault(), CREDENTIAL, "password", CONSUMER),
        Ok(ManagedRead::Refused)
    ));

    let mut record = operation_record(
        WIRE_V3,
        "adopt",
        CREDENTIAL,
        "submitting",
        Some(directory.clone()),
        None,
    );
    record
        .as_object_mut()
        .expect("operation record object")
        .insert("adopt_shape".to_string(), json!("created"));
    lab.save_record(CREDENTIAL, &record);

    // The exact verification path may read it; nobody else may.
    assert!(!candidate_hidden(
        &lab.vault(),
        CREDENTIAL,
        "password",
        CONSUMER
    ));
    assert!(candidate_hidden(
        &lab.vault(),
        CREDENTIAL,
        "password",
        "another-consumer"
    ));
    assert!(candidate_hidden(
        &lab.vault(),
        CREDENTIAL,
        "totp_secret",
        CONSUMER
    ));
}

// ---------------------------------------------------------------------------
// 9. capability shape
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_and_reseal_capabilities_are_item_scoped_without_a_field() {
    let lab = Lab::new();
    lab.managed_login(CREDENTIAL, "current-password");
    for action in ["lifecycle", "reseal"] {
        // One consumer per grant: token-mint refuses to silently widen an
        // existing one, which is a different contract from this test's.
        let consumer = format!("driver-{action}");
        refusal(
            lab.mint(&consumer, &format!("{action}:{CREDENTIAL}#password")),
            "item-scoped and must not name a field",
        );
        accepted(lab.mint(&consumer, &format!("{action}:{CREDENTIAL}")));
    }
    refusal(
        lab.mint("driver", "lifecycle:no-such-item"),
        "capability names a missing item",
    );
}

#[test]
fn a_lifecycle_capability_cannot_share_a_grant_with_read() {
    let lab = Lab::new();
    lab.managed_login(CREDENTIAL, "current-password");
    refusal(
        lab.mint(
            "driver",
            &format!("lifecycle:{CREDENTIAL},read:{CREDENTIAL}#password"),
        ),
        "cannot share a grant with read capabilities",
    );
    refusal(
        lab.mint(
            "driver",
            &format!("read:{CREDENTIAL}#password,lifecycle:{CREDENTIAL}"),
        ),
        "cannot share a grant with read capabilities",
    );
    assert!(lab
        .vault()
        .doc()
        .get("tokens")
        .and_then(|tokens| tokens.get("driver"))
        .is_none());
}

#[test]
fn a_lifecycle_grant_cannot_read_the_value_it_drives() {
    let lab = Lab::new();
    lab.managed_login(CREDENTIAL, "current-password");
    let token = accepted(lab.mint("driver", &format!("lifecycle:{CREDENTIAL}")));
    let vault = lab.vault();

    assert!(
        tokens::token_allows_action(&vault, "driver", &token, "lifecycle", CREDENTIAL)
            .expect("evaluate the lifecycle capability")
    );
    assert!(
        !tokens::token_allows_field_action(
            &vault, "driver", &token, "read", CREDENTIAL, "password"
        )
        .expect("evaluate the read capability"),
        "a lifecycle grant read the value it drives"
    );
    assert!(
        !tokens::token_allows_action(&vault, "driver", &token, "read", CREDENTIAL)
            .expect("evaluate the read capability")
    );
    assert!(
        !tokens::token_allows_action(&vault, "driver", &token, "reseal", CREDENTIAL)
            .expect("evaluate the reseal capability")
    );
    assert!(
        !tokens::token_allows_action(&vault, "driver", &token, "admin", CREDENTIAL)
            .expect("evaluate the admin capability")
    );
}

// ---------------------------------------------------------------------------
// 10. rotate and reset stay apart
// ---------------------------------------------------------------------------

#[test]
fn rotate_is_refused_when_no_managed_value_is_known() {
    let lab = Lab::new();
    lab.install_bridge(&[(
        "submit",
        bridge_reply(
            "operation_queued",
            "rotate",
            GENERIC_PROVIDER,
            CREDENTIAL,
            &[("actionLogId", json!(ACTION_LOG_ID))],
        ),
    )]);
    let rotate = |lab: &Lab| {
        lab.credential(
            &["rotate", CREDENTIAL],
            &[
                ("provider", GENERIC_PROVIDER),
                ("consumer", CONSUMER),
                ("local", "true"),
            ],
        )
    };

    // No item at all.
    refusal(rotate(&lab), "not an active Weles-managed credential");
    // An item nobody manages.
    lab.owner_login(CREDENTIAL, "operator-password");
    refusal(rotate(&lab), "not an active Weles-managed credential");
    assert!(
        lab.bridge_calls().is_empty(),
        "a rotate with no managed value must never reach the bridge"
    );
}

#[test]
fn rotate_is_refused_while_an_adoption_is_still_unconfirmed() {
    let lab = Lab::new();
    lab.seal(CREDENTIAL);
    let directory = sealed_wire_block();
    let staging = AdoptStaging {
        shape: AdoptShape::Created,
        credential_id: CREDENTIAL,
        field: "password",
        consumer: CONSUMER,
        request_id: EVIDENCE_DIGEST,
        account: None,
        directory: Some(&directory),
    };
    accepted(stage_adopted_candidate(
        &lab.vault_path,
        &staging,
        "operator-supplied-password",
    ));
    lab.install_bridge(&[(
        "submit",
        bridge_reply(
            "operation_queued",
            "rotate",
            IDENTITY_PROVIDER,
            CREDENTIAL,
            &[("actionLogId", json!(ACTION_LOG_ID))],
        ),
    )]);
    refusal(
        lab.credential(
            &["rotate", CREDENTIAL],
            &[
                ("provider", IDENTITY_PROVIDER),
                ("consumer", CONSUMER),
                ("local", "true"),
            ],
        ),
        "is adopting, not managed",
    );
    assert!(lab.bridge_calls().is_empty());
}

#[test]
fn a_dry_run_rotate_stays_a_plan_and_commits_nothing() {
    let lab = Lab::new();
    lab.install_bridge(&[(
        "submit",
        bridge_reply(
            "operation_plan",
            "rotate",
            GENERIC_PROVIDER,
            CREDENTIAL,
            &[],
        ),
    )]);
    let planned = accepted(lab.credential(
        &["rotate", CREDENTIAL],
        &[
            ("provider", GENERIC_PROVIDER),
            ("consumer", CONSUMER),
            ("dry-run", "true"),
            ("local", "true"),
        ],
    ));
    assert_eq!(planned.get("ok"), Some(&json!(true)));
    assert_eq!(
        lab.bridge_request().get("dry_run"),
        Some(&json!(true)),
        "a dry run must announce itself on the wire"
    );

    let vault = lab.vault();
    assert!(vault.get_item(CREDENTIAL).is_err());
    assert!(vault.get_item(&request_item_id(CREDENTIAL)).is_err());
    assert!(!lab.lock_path().exists());
    refusal(
        lab.credential(&["status", CREDENTIAL], &[("local", "true")]),
        "no credential or operation request exists",
    );
}

#[test]
fn reset_requires_a_directory_provider() {
    let directory = sealed_wire_block();
    accepted(provider_contract(
        "reset",
        IDENTITY_PROVIDER,
        CREDENTIAL,
        None,
        Some(&directory),
    ));
    refusal(
        provider_contract(
            "reset",
            ACCOUNT_PROVIDER,
            CREDENTIAL,
            Some(ACCOUNT_UPN),
            None,
        ),
        "cannot reset an unknown current password",
    );
    refusal(
        provider_contract("reset", GENERIC_PROVIDER, CREDENTIAL, None, None),
        "has no credential reset contract",
    );
    refusal(
        provider_contract("reset", IDENTITY_PROVIDER, CREDENTIAL, None, None),
        "has no sealed directory contract",
    );

    let lab = Lab::new();
    lab.install_bridge(&[(
        "submit",
        bridge_reply("operation_plan", "reset", GENERIC_PROVIDER, CREDENTIAL, &[]),
    )]);
    refusal(
        lab.credential(
            &["reset", CREDENTIAL],
            &[
                ("provider", GENERIC_PROVIDER),
                ("consumer", CONSUMER),
                ("dry-run", "true"),
                ("local", "true"),
            ],
        ),
        "has no credential reset contract",
    );
    assert!(lab.bridge_calls().is_empty());
}

// ---------------------------------------------------------------------------
// 11. The item's field is a contract, never a mapping
// ---------------------------------------------------------------------------

#[test]
fn an_item_whose_field_is_not_the_contract_field_is_refused_by_name() {
    let lab = Lab::new();
    lab.managed_field(CREDENTIAL, NONCANONICAL_FIELD, "current-password");
    lab.seal(CREDENTIAL);
    lab.install_bridge(&[(
        "submit",
        bridge_reply(
            "operation_queued",
            "rotate",
            IDENTITY_PROVIDER,
            CREDENTIAL,
            &[("actionLogId", json!(ACTION_LOG_ID))],
        ),
    )]);
    let refused = refusal(
        lab.credential(
            &["rotate", CREDENTIAL],
            &[
                ("provider", IDENTITY_PROVIDER),
                ("consumer", CONSUMER),
                ("local", "true"),
            ],
        ),
        FIELD_CONTRACT_MISMATCH,
    );
    // Both names, so nobody has to guess which one the provider writes.
    assert!(
        refused.contains(NONCANONICAL_FIELD) && refused.contains(CANONICAL_FIELD),
        "the refusal does not name both fields: {refused}"
    );
    assert!(
        lab.bridge_calls().is_empty(),
        "a field the item does not carry reached the bridge"
    );
    assert!(
        lab.vault().get_item(&request_item_id(CREDENTIAL)).is_err(),
        "a refused operation left an operation record behind"
    );
}

#[test]
fn no_alias_maps_login_password_onto_the_contract_field() {
    // One provider, one exact field name, for every caller that asks.
    assert_eq!(contract_field(IDENTITY_PROVIDER), CANONICAL_FIELD);
    assert_eq!(contract_field(ACCOUNT_PROVIDER), CANONICAL_FIELD);

    let lab = Lab::new();
    lab.managed_field(CREDENTIAL, NONCANONICAL_FIELD, "current-password");
    lab.seal(CREDENTIAL);
    let baseline = item_revision(&lab.vault(), CREDENTIAL).expect("managed item revision");
    lab.install_bridge(&[(
        "submit",
        bridge_reply(
            "operation_queued",
            "rotate",
            IDENTITY_PROVIDER,
            CREDENTIAL,
            &[("actionLogId", json!(ACTION_LOG_ID))],
        ),
    )]);
    for operation in ["rotate", "verify", "reset"] {
        refusal(
            lab.credential(
                &[operation, CREDENTIAL],
                &[
                    ("provider", IDENTITY_PROVIDER),
                    ("consumer", CONSUMER),
                    ("local", "true"),
                ],
            ),
            FIELD_CONTRACT_MISMATCH,
        );
    }
    assert!(
        lab.bridge_calls().is_empty(),
        "an item carrying only {NONCANONICAL_FIELD} was submitted as {CANONICAL_FIELD}"
    );

    // Nothing was migrated behind the operator: no second field, no staged
    // revision, not even a new revision of the item.
    let payload = lab.vault().get_item(CREDENTIAL).expect("read the item");
    assert_eq!(
        keys_of(payload.get("fields").expect("the item fields")),
        vec![NONCANONICAL_FIELD.to_string()]
    );
    assert!(
        schema::field(&payload, CANONICAL_FIELD).is_err(),
        "{CANONICAL_FIELD} was created beside {NONCANONICAL_FIELD}"
    );
    assert_eq!(item_revision(&lab.vault(), CREDENTIAL), Some(baseline));
    assert!(
        lab.vault()
            .doc()
            .get("items")
            .and_then(|items| items.get(CREDENTIAL))
            .and_then(|item| item.get("pending"))
            .is_none(),
        "a refused operation staged a revision"
    );
}

// ---------------------------------------------------------------------------
// 12. Lifecycle eligibility answered by one command
// ---------------------------------------------------------------------------

#[test]
fn status_reports_a_pre_v2_item_without_a_directory_as_ineligible() {
    let lab = Lab::new();
    lab.legacy_item(CREDENTIAL, NONCANONICAL_FIELD, "current-password");
    let reported = accepted(status_once(&lab.vault_path, &[CREDENTIAL.to_string()]));

    assert_eq!(text_of(&reported, "lifecycle_state"), STATE_UNMANAGED);
    assert_eq!(reported.get("directory"), Some(&Value::Null));
    assert_eq!(reported.get("lifecycle_eligible"), Some(&json!(false)));
    assert_eq!(
        blocker_reasons(&reported),
        vec![
            BLOCKER_LEGACY_ENVELOPE.to_string(),
            BLOCKER_NO_DIRECTORY_CONTRACT.to_string(),
        ]
    );
}

#[test]
fn status_reports_a_sealed_managed_item_with_the_contract_field_as_eligible() {
    let lab = Lab::new();
    lab.managed_login(CREDENTIAL, "current-password");
    lab.seal(CREDENTIAL);
    let reported = accepted(status_once(&lab.vault_path, &[CREDENTIAL.to_string()]));

    assert_eq!(text_of(&reported, "lifecycle_state"), STATE_MANAGED);
    assert_eq!(reported.get("lifecycle_eligible"), Some(&json!(true)));
    assert_eq!(blocker_reasons(&reported), Vec::<String>::new());
}

#[test]
fn every_lifecycle_blocker_is_reported_not_only_the_first() {
    let lab = Lab::new();
    lab.managed_field(CREDENTIAL, NONCANONICAL_FIELD, "current-password");
    let mut frozen = operation_record(WIRE_V3, "rotate", CREDENTIAL, STATE_QUARANTINED, None, None);
    frozen
        .as_object_mut()
        .expect("the operation record is an object")
        .insert("provider".to_string(), json!(IDENTITY_PROVIDER));
    lab.save_record(CREDENTIAL, &frozen);
    let reported = accepted(status_once(&lab.vault_path, &[CREDENTIAL.to_string()]));

    // Three independent reasons, reported together: an operator fixes them in
    // one pass instead of discovering the next one per attempt.
    assert_eq!(reported.get("lifecycle_eligible"), Some(&json!(false)));
    assert_eq!(
        blocker_reasons(&reported),
        vec![
            BLOCKER_NONCANONICAL_FIELD.to_string(),
            BLOCKER_NO_DIRECTORY_CONTRACT.to_string(),
            BLOCKER_QUARANTINED.to_string(),
        ]
    );
    let field_blocker = blocker_detail(&reported, BLOCKER_NONCANONICAL_FIELD);
    assert!(
        field_blocker.contains(NONCANONICAL_FIELD) && field_blocker.contains(CANONICAL_FIELD),
        "the field blocker does not name both fields: {field_blocker}"
    );
}
