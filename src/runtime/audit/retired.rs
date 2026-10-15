// The loopback ports retired units answered on, as the journal recorded them.

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::BufRead;

use super::journal::audit_path;

/// Every loopback port a `unit-retired` entry says a retired unit answered on.
///
/// A host the one process converged before it kept those ports beside the
/// vault has them here and nowhere else. Only lines naming that operation are
/// parsed, so a long journal costs one pass of reading, once per host. A
/// journal that does not exist names no port; one that cannot be read, or a
/// `unit-retired` line whose ports cannot be read, is the error, because the
/// ports it drops would go unanswered with nothing said.
pub fn retired_ports() -> Result<BTreeSet<u16>> {
    let path = audit_path();
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BTreeSet::new());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("open audit journal {}", path.display()));
        }
    };
    let mut ports = BTreeSet::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line.with_context(|| format!("read audit journal {}", path.display()))?;
        if !line.contains("\"op\":\"unit-retired\"") {
            continue;
        }
        let entry: Value = serde_json::from_str(&line).with_context(|| {
            format!(
                "audit journal {} holds a unit-retired line that is not JSON: {line}",
                path.display()
            )
        })?;
        let listed = entry["extra"]["ports"].as_array().with_context(|| {
            format!(
                "audit journal {} holds a unit-retired entry with no list of ports: {line}",
                path.display()
            )
        })?;
        for port in listed {
            let answered = port.as_u64().map(u16::try_from);
            let Some(Ok(answered)) = answered else {
                anyhow::bail!(
                    "audit journal {} holds a unit-retired entry whose {port} is not a port: {line}",
                    path.display()
                );
            };
            ports.insert(answered);
        }
    }
    Ok(ports)
}
