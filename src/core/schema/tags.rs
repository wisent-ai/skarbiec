// Tag namespaces: which prefixed tags a writer may add, and the refusal that
// names the registered ones when it may not.

use anyhow::{bail, Result};
use serde_json::Value;

use super::{exact_token, MAX_NAME_CHARS};

/// One registered tag namespace, and the two shapes a namespace comes in.
///
/// The shapes are not interchangeable and flattening them into one prefix test
/// is what leaves the surface open. `brama:subscription` is the whole
/// statement — an item either is a subscription or is not — and
/// `brama:subscription:anything` is a different, unowned tag that a prefix test
/// would wave through. `brama:agent:` is the opposite: the prefix alone says
/// nothing, the agent name is the content, and a bare `brama:agent:` is a
/// declaration with its subject missing. So an exact namespace matches only
/// itself, and a valued namespace demands a value that clears the same bound
/// every other exact name in this crate clears.
enum TagNamespace {
    /// A tag that is the entire contract; it must match exactly.
    Exact(&'static str),
    /// A prefix whose value names what the role points at. `value` is the
    /// placeholder an operator reads back in a refusal, never part of the match.
    Valued {
        prefix: &'static str,
        value: &'static str,
    },
}

/// The registry. This is the authority: a namespace exists because it is here,
/// and the published table documents what this list already enforces.
///
/// Registering a namespace is adding a row here in the same commit that starts
/// writing it. Nothing else registers anything.
const TAG_NAMESPACES: &[TagNamespace] = &[
    TagNamespace::Exact("managed:weles"),
    TagNamespace::Exact("brama:subscription"),
    TagNamespace::Valued {
        prefix: "brama:agent:",
        value: "agent",
    },
    TagNamespace::Valued {
        prefix: "brama:provider:",
        value: "provider",
    },
    TagNamespace::Valued {
        prefix: "brama:id:",
        value: "id",
    },
    // Which login item a Codex subscription belongs to. `credential status
    // <id> reauth` treats an item as that subscription only when it carries
    // this tag alongside `brama:subscription` and `brama:provider:codex`
    // (`credential::status::named_subscription_present`), so the product reads
    // this namespace and decides on it. Leaving it unregistered meant the
    // binary demanded a tag it refused to let anyone write: every other tag
    // that workflow needs passed the gate and this one did not.
    TagNamespace::Valued {
        prefix: "brama:login:",
        value: "login",
    },
    TagNamespace::Exact("fleet:host-account"),
    TagNamespace::Valued {
        prefix: "fleet:target:",
        value: "name",
    },
    TagNamespace::Exact("fleet:tailnet-tls"),
    // Written by the credential lifecycle when it freezes an item, and read
    // back by `record_quarantined` to decide whether an item is frozen. The
    // product both writes and reads it, so it is a namespace this vault uses
    // and belongs here; describing it as a gap elsewhere is not the same as
    // closing it.
    TagNamespace::Exact("lifecycle:quarantined"),
];

impl TagNamespace {
    fn shown(&self) -> String {
        match self {
            TagNamespace::Exact(tag) => (*tag).to_string(),
            TagNamespace::Valued { prefix, value } => format!("{prefix}<{value}>"),
        }
    }
}

/// Why one tag is refused, or `Ok` if a registered namespace covers it.
///
/// A tag carrying no colon claims no namespace: it is an operator's own label,
/// governed by nobody and filtered on by nobody, and the registry has no
/// standing over it. This crate writes two of them itself — `onboarding` and
/// `challenge` — and refusing them would refuse the onboarding walkthrough and
/// the Apple challenge record. A colon is the claim, and a claim is what has to
/// be honoured.
fn tag_refusal(tag: &str) -> Result<(), String> {
    if !tag.contains(':') {
        return Ok(());
    }
    if TAG_NAMESPACES
        .iter()
        .any(|namespace| matches!(namespace, TagNamespace::Exact(exact) if tag == *exact))
    {
        return Ok(());
    }
    for namespace in TAG_NAMESPACES {
        let TagNamespace::Valued { prefix, value } = namespace else {
            continue;
        };
        let Some(carried) = tag.strip_prefix(prefix) else {
            continue;
        };
        if exact_token(carried, MAX_NAME_CHARS) {
            return Ok(());
        }
        return Err(format!(
            "claims the {prefix}<{value}> namespace without a usable {value}: the value must be 1 to {MAX_NAME_CHARS} bytes and carry no NUL, newline or carriage return"
        ));
    }
    Err("claims a namespace that is not registered".to_string())
}

/// The refusal an operator reads. It names the tag, says what is wrong with it,
/// and lists what is allowed, because a refusal that withholds the allowed set
/// only moves the guessing one step along.
fn tag_refused(tag: &str, reason: &str) -> String {
    let registered: Vec<String> = TAG_NAMESPACES.iter().map(TagNamespace::shown).collect();
    format!(
        "tag `{tag}` {reason}. Registered namespaces: {}. Register a namespace before anything writes it; a tag with no colon claims no namespace and stays the operator's own label.",
        registered.join(", ")
    )
}

/// Refuse a write that introduces a tag no registered namespace covers.
///
/// Only what this write introduces. A tag the item already carries is left
/// alone: writes deliberately preserve tags they do not mention, and re-reading
/// that preserved list through this gate would turn every unrelated rotation of
/// an already-tagged item into a refusal — which is the tag-loss failure the
/// preserving write was added to end, arriving by the other door. An
/// unregistered tag already in the vault is a migration to run, not a rotation
/// to break.
pub fn ensure_registered_tags(carried: &[Value], written: &[Value]) -> Result<()> {
    for tag in written.iter().filter_map(Value::as_str) {
        if carried.iter().any(|kept| kept.as_str() == Some(tag)) {
            continue;
        }
        if let Err(reason) = tag_refusal(tag) {
            bail!("{}", tag_refused(tag, &reason));
        }
    }
    Ok(())
}
