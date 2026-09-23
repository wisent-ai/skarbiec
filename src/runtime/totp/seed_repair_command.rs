use super::*;

/// The exact operator path that stores a seed. Named in the diagnostic's own
/// output because a verdict an operator cannot act on is a verdict nobody
/// acts on. The seed arrives on standard input — never in an argument, where
/// it would sit in every process table on the host.
pub const SEED_REPAIR_COMMAND: &str =
    "send the complete updated login JSON with totp_secret on stdin to \
     skarbiec set-json <login-item> --type login; preserve the item's other fields";

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
                "replace the placeholder account values with a real account first; then enrol TOTP and send the complete updated login JSON with totp_secret on stdin to skarbiec set-json <login-item> --type login",
            ),
            Self::Invalid => Some(
                "replace the invalid totp_secret with the real Base32 seed from the account's authenticator enrolment; send the complete updated login JSON on stdin to skarbiec set-json <login-item> --type login",
            ),
            Self::DeclaredEmpty => Some(SEED_REPAIR_COMMAND),
            Self::FieldAbsent => Some(
                "this row's kind declares no totp_secret field; \
                 store the account as a `login` item before storing a seed",
            ),
        }
    }
}

/// Where one item's second factor actually lives, and the payload to judge.
///
/// A platform login carries its own `totp_secret` only while the seed has
/// nowhere better to be. When it names an identity in `context.identity`, the
/// factor belongs to that identity: one Google account holds the authenticator
/// and a dozen platform rows sign in as it. Resolving here rather than in each
/// caller keeps `totp` and `totp-seed-state` answering about the same seed.
pub(crate) struct Resolved {
    pub(crate) payload: Value,
    pub(crate) identity: Option<String>,
}

pub(crate) fn resolve(vault: &Vault, payload: Value) -> Resolved {
    if seed_of(&payload).is_some() {
        return Resolved {
            payload,
            identity: None,
        };
    }
    let Some(reference) = payload
        .get("context")
        .and_then(|context| context.get(schema::IDENTITY_REFERENCE))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|seed| !seed.is_empty())
        .map(str::to_string)
    else {
        return Resolved {
            payload,
            identity: None,
        };
    };
    match vault.get_item(&reference) {
        Ok(identity_payload) => Resolved {
            payload: identity_payload,
            identity: Some(reference),
        },
        // The write path refuses a reference to an item that is not there, so
        // an unreadable identity is a key or envelope fault, not a dangling
        // name. The login's own payload is judged and the identity is still
        // named, so the report says which row could not be opened.
        Err(_) => Resolved {
            payload,
            identity: Some(reference),
        },
    }
}

/// Classify one canonical item payload. Reads the seed only to ask whether it
/// is there; the value never leaves this function.
pub fn seed_state(payload: &Value) -> SeedState {
    if seed_of(payload).is_some() {
        return SeedState::Present;
    }
    let declares = payload
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| schema::kind_allows_field(kind, "totp_secret"));
    if declares {
        SeedState::DeclaredEmpty
    } else {
        SeedState::FieldAbsent
    }
}
