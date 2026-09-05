// One-time-code helper. For a canonical login item that stores a base32 seed,
// emit the CURRENT time-based code (via the standard oath toolkit) — like a
// password manager's built-in authenticator. The seed value itself is never
// emitted; only the short-lived code.
//
// This module also answers the vault's half of "is the stored authenticator
// seed still the one the account has enrolled". The vault cannot answer the
// whole question: whether a seed still MATCHES an enrolment is only observable
// where codes are submitted, which is the Weles reauth run history that
// `stado host weles-seed-freshness` reads. What the vault alone can prove is
// which of three states a login row is in, and those three have three
// different repairs, so they are never collapsed here.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{crypto, schema, vault::Vault, vault_path};

/// The exact operator path that stores a seed. Named in the diagnostic's own
/// output because a verdict an operator cannot act on is a verdict nobody
/// acts on. The seed arrives on standard input — never in an argument, where
/// it would sit in every process table on the host.
pub const SEED_REPAIR_COMMAND: &str = "printf '%s' '<seed from the authenticator app>' \
     | ACCOUNT=<login-item> skarbiec/scripts/store-login-totp-seed.sh";

/// What the vault can prove about one login row's authenticator seed.
///
/// `Present` is deliberately NOT "current": a valid seed that is stale looks
/// exactly like a valid seed that still matches the enrolment from inside the
/// vault. Splitting those states needs submitted-code evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedState {
    /// A Base32 value accepted by the real TOTP consumer, which produced one
    /// six-digit code.
    Present,
    /// A non-empty uppercase underscore-delimited placeholder, not a secret.
    Placeholder,
    /// A non-empty value that is not usable as a Base32 TOTP seed.
    Invalid,
    /// The row's kind declares `totp_secret`, and the row carries no usable
    /// value for it — absent, empty, blank, or not a string.
    DeclaredEmpty,
    /// The row's kind has no `totp_secret` field at all. Storing a seed here is
    /// refused by the schema; the row's kind is the thing that is wrong.
    FieldAbsent,
}

impl SeedState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Placeholder => "placeholder",
            Self::Invalid => "invalid",
            Self::DeclaredEmpty => "declared_empty",
            Self::FieldAbsent => "field_absent",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Present => {
                "totp_secret contains a usable Base32 seed that produced a six-digit TOTP code; whether it still matches the account enrolment is unknown"
            }
            Self::Placeholder => {
                "totp_secret contains an uppercase underscore-delimited placeholder, not a TOTP seed; no usable second-factor secret is stored"
            }
            Self::Invalid => {
                "totp_secret is non-empty but is not a usable Base32 TOTP seed and did not produce a six-digit code; no usable second-factor secret is stored"
            }
            Self::DeclaredEmpty => {
                "this item kind declares totp_secret, but the field is absent, empty, blank, or not text; no second-factor secret is stored"
            }
            Self::FieldAbsent => {
                "this item kind does not declare a totp_secret field; the item cannot store a TOTP second factor in its current shape"
            }
        }
    }

    /// Every settled failure carries the first correct operator action.
    pub fn repair(self) -> Option<&'static str> {
        match self {
            Self::Present => None,
            Self::Placeholder => Some(
                "replace the placeholder account values with a real account first; then enrol TOTP and store its Base32 seed with \
                 printf '%s' '<seed from the authenticator app>' | ACCOUNT=<login-item> skarbiec/scripts/store-login-totp-seed.sh",
            ),
            Self::Invalid => Some(
                "replace the invalid totp_secret with the real Base32 seed from the account's authenticator enrolment using \
                 printf '%s' '<seed from the authenticator app>' | ACCOUNT=<login-item> skarbiec/scripts/store-login-totp-seed.sh",
            ),
            Self::DeclaredEmpty => Some(SEED_REPAIR_COMMAND),
            Self::FieldAbsent => Some(
                "this row's kind declares no totp_secret field; \
                 store the account as a `login` item before storing a seed",
            ),
        }
    }
}

fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

/// The non-blank text stored in `totp_secret`, if there is any.
fn seed_of(payload: &Value) -> Option<&str> {
    schema::field(payload, "totp_secret")
        .ok()
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|seed| !seed.is_empty())
}

/// TOTP seeds in this product are Base32 text, optionally followed by standard
/// `=` padding. Sixteen data characters is the shortest supported seed (80
/// bits); 128 keeps diagnostic work bounded.
fn base32_seed_shape(seed: &str) -> bool {
    let data = seed.trim_end_matches('=');
    let padding = seed.len().saturating_sub(data.len());
    ("16".parse::<usize>().unwrap_or_default()..="128".parse().unwrap_or(usize::MAX))
        .contains(&data.len())
        && padding <= 6
        && (padding == usize::MIN || seed.len() % 8 == usize::MIN)
        && data
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || matches!(byte, b'2'..=b'7'))
}

struct SeedInspection {
    state: SeedState,
    code: Option<String>,
}

/// Classify one canonical item payload against the same TOTP consumer used by
/// `totp`. The seed never leaves this function; only the six-digit result can.
fn inspect_seed(payload: &Value) -> SeedInspection {
    let Some(seed) = seed_of(payload) else {
        let declares = payload
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| schema::kind_declares_field(kind, "totp_secret"));
        return SeedInspection {
            state: if declares {
                SeedState::DeclaredEmpty
            } else {
                SeedState::FieldAbsent
            },
            code: None,
        };
    };
    if schema::is_placeholder(seed) {
        return SeedInspection {
            state: SeedState::Placeholder,
            code: None,
        };
    }
    if !base32_seed_shape(seed) {
        return SeedInspection {
            state: SeedState::Invalid,
            code: None,
        };
    }
    match crypto::totp_code(seed) {
        Some(code) => SeedInspection {
            state: SeedState::Present,
            code: Some(code),
        },
        None => SeedInspection {
            state: SeedState::Invalid,
            code: None,
        },
    }
}

pub fn seed_state(payload: &Value) -> SeedState {
    inspect_seed(payload).state
}

pub fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "totp" => {
            let id = positionals.first().context("usage: totp <item-id>")?;
            let vault = load()?;
            let row = vault.get_item(id)?;
            let inspected = inspect_seed(&row);
            let state = inspected.state;
            Ok(Some(json!({
                "item": id,
                "has_seed": state == SeedState::Present,
                "seed_state": state.as_str(),
                "description": state.description(),
                "code": inspected.code,
                "repair": state.repair().map(|repair| repair.replace("<login-item>", id)),
            })))
        }
        // The seed-state diagnostic validates the stored value through the same
        // real TOTP computation as `totp`, but never returns the short-lived
        // code or the seed itself.
        "totp-seed-state" => {
            let vault = load()?;
            // One item, or every login row in one vault open. The sweep form
            // exists because the caller is a fleet diagnostic: asking per row
            // over a host channel would open the vault once per account.
            let ids: Vec<String> = match positionals.first() {
                Some(id) => vec![id.clone()],
                None => vault
                    .list(false)
                    .iter()
                    .filter(|row| row.get("kind").and_then(Value::as_str) == Some("login"))
                    .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_string))
                    .collect(),
            };
            let rows: Vec<Value> = ids
                .iter()
                .map(|id| match vault.get_item(id) {
                    Ok(row) => {
                        let state = seed_state(&row);
                        json!({
                            "item": id,
                            "kind": row.get("kind").cloned().unwrap_or(Value::Null),
                            "seed_state": state.as_str(),
                            "description": state.description(),
                            // The repair names the account it is for; a
                            // command an operator has to edit before running
                            // is a command they run wrong.
                            "repair": state.repair().map(|repair| repair.replace("<login-item>", id)),
                        })
                    }
                    // A row this vault cannot open is reported as itself, not
                    // silently dropped and not guessed at: "no seed" and "the
                    // envelope is unreadable" have nothing in common.
                    Err(error) => json!({
                        "item": id,
                        "kind": Value::Null,
                        "seed_state": "unreadable",
                        "error": error.to_string(),
                    }),
                })
                .collect();
            if !positionals.is_empty() {
                return Ok(Some(rows.into_iter().next().unwrap_or(Value::Null)));
            }
            Ok(Some(json!({"rows": rows})))
        }
        _ => Ok(None),
    }
}
