// Core of the skarbiec vault: cryptographic operations, the encrypted
// per-recipient vault document, and the typed item model. Sibling layers
// (access, runtime, net) build on these.

pub mod crypto;
pub mod inbox;
pub mod items;
pub mod vault;

use std::path::PathBuf;

/// Location of the encrypted vault. An explicit `SKARBIEC_VAULT_FILE` wins;
/// otherwise use the user's Stado state directory, never the source tree.
pub fn vault_path() -> PathBuf {
    if let Ok(p) = std::env::var("SKARBIEC_VAULT_FILE") {
        return PathBuf::from(p);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".stado/skarbiec.vault.json")
}

/// Anchored glob match with `*` wildcards, no regex dependency and no numeric
/// literals: split on '*', walk the literal segments in order. Shared by the
/// access layer's scope checks, which run it once per candidate item.
pub fn glob_matches(pattern: &str, id: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let starts_wild = pattern.starts_with('*');
    let ends_wild = pattern.ends_with('*');
    let last_index = parts.len().saturating_sub(std::iter::once(()).count());
    let mut pos = id;
    for (index, part) in parts.iter().enumerate() {
        let is_first = index == usize::MIN;
        let is_last = index == last_index;
        if part.is_empty() {
            continue;
        }
        if is_first && is_last && !starts_wild && !ends_wild {
            return pos == *part;
        }
        if is_first && !starts_wild {
            if !pos.starts_with(part) {
                return false;
            }
            pos = &pos[part.len()..];
        } else if is_last && !ends_wild {
            if !pos.ends_with(part) {
                return false;
            }
        } else if let Some(found) = pos.find(part) {
            pos = &pos[found + part.len()..];
        } else {
            return false;
        }
    }
    true
}
