//! The Skarbiec units a host ran beside the one Skarbiec process, and how that
//! process takes over their work when launchd starts it as its declared unit.
//!
//! A host kept up to five Skarbiec processes: this service, a second `serve`
//! for the control plane, the keychain launcher's `serve`, a `serve` of the
//! retired Weles-only vault, and the removed `sync-daemon`. Started as
//! `com.wisent.always-on.skarbiec`, the one process records the replica
//! daemon's bearer file and consumer on its bond, notes the loopback ports
//! every predecessor was listening on, boots each unit out and removes its
//! launch agent, and then listens on those ports itself: a consumer still
//! dialling an old port reaches the one process, and no install finds a plist
//! to load again. The ports are kept beside the vault, so every later start of
//! the declared unit answers on them too. Only a unit whose launch agent is in
//! this user's `~/Library/LaunchAgents` is retired, and a test or an operator
//! running `serve` by hand retires nothing.

use std::collections::BTreeSet;

/// The label the fleet runs the one Skarbiec process under.
pub(crate) const DECLARED_UNIT: &str = "com.wisent.always-on.skarbiec";

/// Units whose work runs inside the one process.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const PREDECESSORS: [&str; 4] = [
    "com.wisent.compute.service.skarbiec-replica-sync",
    "com.wisent.compute.service.skarbiec-control-plane",
    "com.wisent.skarbiec",
    "com.wisent.compute.service.com.wisent.skarbiec-weles",
];

/// Retire every predecessor present on this host when this process is the
/// declared unit, and return the loopback ports it answers on in their place:
/// the ones retired now and the ones earlier starts inherited.
pub(crate) fn take_over() -> BTreeSet<u16> {
    let declared = std::env::var("XPC_SERVICE_NAME").is_ok_and(|label| label == DECLARED_UNIT);
    if !declared {
        return BTreeSet::new();
    }
    let (mut ports, recorded) = super::inherited::remembered();
    let retired = launchd::take_over();
    let grown = !retired.is_subset(&ports);
    ports.extend(retired);
    if grown || !recorded {
        if let Err(error) = super::inherited::remember(&ports) {
            eprintln!(
                "skarbiec serve: answering on the retired units' ports {ports:?}, but they are not kept for the next start: {error:#}"
            );
        }
    }
    ports
}

#[cfg(target_os = "macos")]
mod launchd {
    use anyhow::{Context, Result};
    use serde_json::{json, Value};
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::PREDECESSORS;
    use crate::core::{vault::Vault, vault_path};

    pub(super) fn take_over() -> BTreeSet<u16> {
        // SAFETY: getuid has no preconditions and cannot fail.
        let domain = format!("gui/{}", unsafe { libc::getuid() });
        let agents = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join("Library/LaunchAgents");
        let mut ports = BTreeSet::new();
        for label in PREDECESSORS {
            let plist = agents.join(format!("{label}.plist"));
            // Retiring a unit is removing this user's launch agent for it. A
            // job with no launch agent here was loaded from somewhere this
            // process does not own, and a fixture with its own HOME must never
            // boot out the real host's jobs.
            if !plist.exists() {
                continue;
            }
            let pid = running_pid(&domain, label);
            let arguments = program_arguments(&plist);
            if arguments.iter().any(|argument| argument == "sync-daemon") {
                if let Err(error) = adopt_replica_bond(&arguments) {
                    eprintln!(
                        "skarbiec serve: kept {label}: its bond could not be recorded, so retiring it would lose the bearer it names: {error:#}"
                    );
                    continue;
                }
            }
            let inherited = pid.map(listening_ports).unwrap_or_default();
            let _ = Command::new("/bin/launchctl")
                .arg("bootout")
                .arg(format!("{domain}/{label}"))
                .output();
            match std::fs::remove_file(&plist) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => eprintln!(
                    "skarbiec serve: {label} is stopped but {} stays: {error}",
                    plist.display()
                ),
            }
            eprintln!(
                "skarbiec serve: retired {label}; this process serves its ports {inherited:?}"
            );
            if let Err(error) = crate::runtime::audit::append(
                "unit-retired",
                &json!({"unit": label, "ports": inherited}),
            ) {
                eprintln!("skarbiec serve: could not journal the retirement of {label}: {error:#}");
            }
            ports.extend(inherited);
        }
        ports
    }

    /// The pid launchd reports for a loaded, running job.
    fn running_pid(domain: &str, label: &str) -> Option<u32> {
        let output = Command::new("/bin/launchctl")
            .arg("print")
            .arg(format!("{domain}/{label}"))
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.trim().strip_prefix("pid = ")?.trim().parse().ok())
    }

    /// Loopback TCP ports the process is listening on.
    fn listening_ports(pid: u32) -> BTreeSet<u16> {
        let Ok(output) = Command::new("/usr/sbin/lsof")
            .args([
                "-nP",
                "-a",
                "-p",
                &pid.to_string(),
                "-iTCP",
                "-sTCP:LISTEN",
                "-Fn",
            ])
            .output()
        else {
            return BTreeSet::new();
        };
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix('n'))
            .filter_map(|address| {
                let (host, port) = address.rsplit_once(':')?;
                ["127.0.0.1", "[::1]", "localhost"]
                    .contains(&host)
                    .then(|| port.parse().ok())
                    .flatten()
            })
            .collect()
    }

    /// The unit's argv, as its launch agent declares it.
    fn program_arguments(plist: &Path) -> Vec<String> {
        Command::new("/usr/bin/plutil")
            .args(["-extract", "ProgramArguments", "json", "-o", "-"])
            .arg(plist)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| serde_json::from_slice::<Vec<String>>(&output.stdout).ok())
            .unwrap_or_default()
    }

    /// The removed `sync-daemon` carried its bond's bearer file and consumer
    /// only in its argv. Record them on the bond's serve channel, the way
    /// `bond-add --token-file --consumer` does, so the replication component
    /// this process starts for the bond pulls exactly what the daemon pulled.
    fn adopt_replica_bond(arguments: &[String]) -> Result<()> {
        let value = |flag: &str| {
            arguments
                .iter()
                .position(|argument| argument == flag)
                .and_then(|index| arguments.get(index + usize::from(true)))
                .cloned()
        };
        let name = value("--bond").context("the unit names no --bond")?;
        let token_file = value("--token-file").context("the unit names no --token-file")?;
        let consumer = value("--consumer").unwrap_or_else(|| "replica".to_string());
        crate::credential::read_secret_file(Path::new(&token_file))
            .with_context(|| format!("the bearer file {token_file} is not readable"))?;
        let mut vault = Vault::open(vault_path())?;
        let channel = vault
            .doc_mut()
            .get_mut("bond")
            .and_then(|bonds| bonds.get_mut(&name))
            .and_then(|bond| bond.get_mut("channel"))
            .and_then(Value::as_object_mut)
            .with_context(|| format!("no bond named {name} in the vault"))?;
        if channel.contains_key("token_file") {
            return Ok(());
        }
        anyhow::ensure!(
            channel.get("type").and_then(Value::as_str) == Some("serve"),
            "bond {name} does not pull over a serve channel"
        );
        anyhow::ensure!(
            channel
                .get("interval_seconds")
                .and_then(Value::as_u64)
                .is_some(),
            "bond {name} has no interval_seconds"
        );
        channel.insert("token_file".to_string(), json!(token_file));
        channel.insert("consumer".to_string(), json!(consumer));
        vault.save()?;
        crate::runtime::audit::append(
            "bond-add",
            &json!({"bond": name, "consumer": consumer, "adopted_from": "sync-daemon"}),
        )?;
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
mod launchd {
    pub(super) fn take_over() -> std::collections::BTreeSet<u16> {
        std::collections::BTreeSet::new()
    }
}
