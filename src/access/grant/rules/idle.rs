// Which consumers have used their grant since a moment, read from the audit
// journal. A grant nobody uses still opens its items to whoever holds its
// bearer, so `grant list --idle-since <iso>` names the ones to withdraw.
// Use is any journal entry naming the consumer that the owner did not write
// about the grant itself: its reads, writes and acquisitions all count, its
// issue, keep, narrow, retarget or revoke do not.

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// The consumers seen in the journal at or after the moment.
pub(in crate::access::grant) struct Seen(HashSet<String>);

impl Seen {
    /// `None` when no moment is given, so every grant passes.
    pub(in crate::access::grant) fn since(moment: Option<&String>) -> Result<Option<Self>> {
        let Some(moment) = moment else {
            return Ok(None);
        };
        if !crate::core::clock::is_iso(moment) {
            return Err(crate::cli::args::Usage(format!(
                "--idle-since {moment} is not a UTC time of the form {}",
                crate::core::clock::now_iso()
            ))
            .into());
        }
        let flags = HashMap::from([("since".to_string(), moment.clone())]);
        let answer = crate::runtime::audit::dispatch("audit", &flags, &["list".to_string()])?
            .context("audit list answered nothing")?;
        let entries = answer
            .get("entries")
            .and_then(Value::as_array)
            .context("audit list answered no entries")?;
        let seen = entries
            .iter()
            .filter(|entry| {
                !entry
                    .get("op")
                    .and_then(Value::as_str)
                    .is_some_and(|op| op.starts_with("grant-"))
            })
            .filter_map(|entry| entry.get("extra")?.get("consumer")?.as_str())
            .map(str::to_string)
            .collect();
        Ok(Some(Self(seen)))
    }

    /// Whether `consumer` left no trace since the moment.
    pub(in crate::access::grant) fn idle(&self, consumer: &str) -> bool {
        !self.0.contains(consumer)
    }
}
