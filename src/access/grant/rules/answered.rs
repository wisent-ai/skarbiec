// Which of a grant's capabilities still name something the vault answers.
// A grant outlives the item it was written for: trash, purge or rename the
// item and the grant keeps naming it, reaching nothing, until someone
// notices. `grant list` says which names no live item answers.

use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeSet;

use crate::core::vault::Vault;

/// The names a capability can reach through: every live item id, and
/// `role:<role>` for every `stado:role:<role>` tag a live item carries.
pub(in crate::access::grant) struct Answerable {
    names: BTreeSet<String>,
}

impl Answerable {
    pub(in crate::access::grant) fn of(vault: &Vault) -> Result<Self> {
        let mut names = BTreeSet::new();
        for entry in vault.list(false) {
            let Some(id) = entry.get("id").and_then(Value::as_str) else {
                continue;
            };
            names.insert(id.to_string());
            let held = vault.doc().get("items").and_then(|items| items.get(id));
            if let Some(held) = held {
                for tag in crate::core::vault::entry_texts(id, held, "tags")? {
                    if let Some(role) = tag.strip_prefix("stado:role:") {
                        names.insert(format!("role:{role}"));
                    }
                }
            }
        }
        Ok(Self { names })
    }

    /// The item names one grant's capabilities hold that nothing live
    /// answers, each once. A capability that names no item (a service
    /// call) is not about items and is never listed.
    pub(in crate::access::grant) fn unanswered(&self, grant: &Value) -> Vec<String> {
        let named: BTreeSet<&str> = grant
            .get("capabilities")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|capability| capability.get("item").and_then(Value::as_str))
            .collect();
        named
            .into_iter()
            .filter(|name| !self.names.contains(*name))
            .map(str::to_string)
            .collect()
    }
}
