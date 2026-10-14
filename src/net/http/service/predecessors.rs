//! The Skarbiec units a host ran beside the one Skarbiec process, and how that
//! process takes over their work when launchd starts it as its declared unit.
//!
//! A host kept up to five Skarbiec processes: this service, a second `serve`
//! for the control plane, the keychain launcher's `serve`, a `serve` of the
//! retired Weles-only vault, and the removed `sync-daemon`. Started as
//! `com.wisent.skarbiec`, the one process records the replica
//! daemon's bearer file and consumer on its bond, notes the loopback ports
//! every predecessor was listening on, boots each unit out and removes its
//! launch agent, and then listens on those ports itself: a consumer still
//! dialling an old port reaches the one process, and no install finds a plist
//! to load again. The ports are kept beside the vault, so every later start of
//! the declared unit answers on them too. Only a unit whose launch agent is in
//! this user's `~/Library/LaunchAgents` is retired, and a test or an operator
//! running `serve` by hand retires nothing.

use std::collections::BTreeSet;

/// The one unit the fleet runs Skarbiec under, as the Stado catalog names it.
pub(crate) const DECLARED_UNIT: &str = "com.wisent.skarbiec";

/// Units whose work runs inside the one process: the catalog's retired units
/// of Skarbiec, in the same order. The capability broker was a second
/// Skarbiec serving only its capability socket under another account.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const PREDECESSORS: [&str; 5] = [
    "com.wisent.compute.service.skarbiec-replica-sync",
    "com.wisent.compute.service.skarbiec-control-plane",
    "com.wisent.always-on.skarbiec",
    "com.wisent.compute.service.com.wisent.skarbiec-weles",
    "com.wisent.skarbiec-capability-broker",
];

/// Whether launchd started this process as the fleet's declared unit; a serve
/// run by hand or by a test is not.
pub(super) fn declared() -> bool {
    std::env::var("XPC_SERVICE_NAME").is_ok_and(|label| label == DECLARED_UNIT)
}

/// Retire every predecessor present on this host when this process is the
/// declared unit, and return the loopback ports it answers on in their place:
/// the ones retired now and the ones earlier starts inherited.
pub(crate) fn take_over() -> BTreeSet<u16> {
    if !declared() {
        return BTreeSet::new();
    }
    // A record that cannot be read is left exactly as it is: this start
    // answers on the ports the journal and launchd name, and says why, but
    // never replaces the record with that partial set.
    let (mut ports, recorded, rewritable) = match super::inherited::remembered() {
        Ok((ports, recorded)) => (ports, recorded, true),
        Err(error) => {
            eprintln!(
                "skarbiec serve: the inherited ports record cannot be read, so it is left as it is and this start answers only on the ports the journal and the retired units name: {error:#}"
            );
            let journal = match crate::runtime::audit::retired_ports() {
                Ok(ports) => ports,
                Err(journal_error) => {
                    eprintln!(
                        "skarbiec serve: the journal cannot name the retired units' ports either, so this start answers only on the ports retired now: {journal_error:#}"
                    );
                    BTreeSet::new()
                }
            };
            (journal, true, false)
        }
    };
    let retired = launchd::take_over();
    let grown = !retired.is_subset(&ports);
    ports.extend(retired);
    if rewritable && (grown || !recorded) {
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
        let Some(home) = std::env::var_os("HOME") else {
            eprintln!(
                "skarbiec serve: HOME is not set, so no predecessor's launch agent can be found and none is taken over"
            );
            return BTreeSet::new();
        };
        let agents = PathBuf::from(home).join("Library/LaunchAgents");
        let mut ports = BTreeSet::new();
        for label in PREDECESSORS {
            let plist = agents.join(format!("{label}.plist"));
            // Retiring a unit is removing this user's launch agent for it. A
            // job with no launch agent here was loaded from somewhere this
            // process does not own, and a fixture with its own HOME must never
            // boot out the real host's jobs.
            match crate::core::is_present(&plist, "predecessor launch agent") {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    eprintln!("skarbiec serve: kept {label}: {error:#}");
                    continue;
                }
            }
            // A unit whose state cannot be read is kept and the cause named:
            // retiring it blind could stop a job whose ports nothing then
            // serves, or lose the bond bearer a sync-daemon carries in argv.
            let pid = match running_pid(&domain, label) {
                Ok(pid) => pid,
                Err(error) => {
                    eprintln!("skarbiec serve: kept {label}: whether it runs could not be read: {error:#}");
                    continue;
                }
            };
            let arguments = match program_arguments(&plist) {
                Ok(arguments) => arguments,
                Err(error) => {
                    eprintln!("skarbiec serve: kept {label}: its launch agent's arguments could not be read: {error:#}");
                    continue;
                }
            };
            if arguments.iter().any(|argument| argument == "sync-daemon") {
                if let Err(error) = adopt_replica_bond(&arguments) {
                    eprintln!(
                        "skarbiec serve: kept {label}: its bond could not be recorded, so retiring it would lose the bearer it names: {error:#}"
                    );
                    continue;
                }
            }
            let inherited = match pid {
                None => BTreeSet::new(),
                Some(pid) => match listening_ports(pid) {
                    Ok(ports) => ports,
                    Err(error) => {
                        eprintln!("skarbiec serve: kept {label} (pid {pid}): the ports it serves could not be read: {error:#}");
                        continue;
                    }
                },
            };
            // A bootout that failed while the old job was running leaves it on
            // its ports: reporting it "retired" and deleting its plist hid a
            // second listener. Such a job is kept and the failure named; a job
            // with no pid has nothing to stop, so its bootout answer is moot.
            let target = format!("{domain}/{label}");
            let bootout =
                stado_wait::output(Command::new("/bin/launchctl").arg("bootout").arg(&target));
            let failure = match bootout {
                Ok(output) if output.status.success() => None,
                Ok(output) => Some(format!(
                    "exited {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                )),
                Err(error) => Some(format!("could not run: {error}")),
            };
            if let (Some(failure), Some(pid)) = (failure, pid) {
                eprintln!(
                    "skarbiec serve: kept {label} (pid {pid}): launchctl bootout {target} {failure}"
                );
                continue;
            }
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

    /// The pid launchd reports for a loaded, running job; none when launchd
    /// has no such job loaded.
    fn running_pid(domain: &str, label: &str) -> Result<Option<u32>> {
        let target = format!("{domain}/{label}");
        let output = stado_wait::output(Command::new("/bin/launchctl").arg("print").arg(&target))
            .map_err(|error| {
            anyhow::anyhow!("launchctl print {target} could not run: {error}")
        })?;
        if !output.status.success() {
            return Ok(None);
        }
        // A pid line that does not parse is the error: read as no pid, a
        // running unit would be retired as if nothing ran.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let Some(pid) = stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("pid = "))
        else {
            return Ok(None);
        };
        pid.trim().parse::<u32>().map(Some).map_err(|error| {
            anyhow::anyhow!("launchctl print {target} answered an unreadable pid {pid:?}: {error}")
        })
    }

    /// Loopback TCP ports the process is listening on. lsof answers a process
    /// with no listening socket with a failed status and nothing on stderr; a
    /// failure that says something is the error.
    fn listening_ports(pid: u32) -> Result<BTreeSet<u16>> {
        let output = stado_wait::output(Command::new("/usr/sbin/lsof").args([
            "-nP",
            "-a",
            "-p",
            &pid.to_string(),
            "-iTCP",
            "-sTCP:LISTEN",
            "-Fn",
        ]))
        .map_err(|error| anyhow::anyhow!("lsof could not run for pid {pid}: {error}"))?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() && !stderr.trim().is_empty() {
            anyhow::bail!(
                "lsof for pid {pid} exited {}: {}",
                output.status,
                stderr.trim()
            );
        }
        // A loopback listener whose port does not parse is the error: dropped,
        // the unit is retired and that port answers nothing.
        let mut ports = BTreeSet::new();
        for address in String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix('n'))
        {
            let Some((host, port)) = address.rsplit_once(':') else {
                continue;
            };
            if !["127.0.0.1", "[::1]", "localhost"].contains(&host) {
                continue;
            }
            ports.insert(port.parse::<u16>().map_err(|error| {
                anyhow::anyhow!(
                    "lsof for pid {pid} listed {address:?} with an unreadable port: {error}"
                )
            })?);
        }
        Ok(ports)
    }

    /// The unit's argv, as its launch agent declares it.
    fn program_arguments(plist: &Path) -> Result<Vec<String>> {
        let output = stado_wait::output(
            Command::new("/usr/bin/plutil")
                .args(["-extract", "ProgramArguments", "json", "-o", "-"])
                .arg(plist),
        )
        .map_err(|error| anyhow::anyhow!("plutil could not run on {}: {error}", plist.display()))?;
        anyhow::ensure!(
            output.status.success(),
            "plutil could not read ProgramArguments of {}: exited {}: {}",
            plist.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        serde_json::from_slice(&output.stdout).with_context(|| {
            format!(
                "ProgramArguments of {} is not a list of strings",
                plist.display()
            )
        })
    }

    /// The removed `sync-daemon` carried its bond's bearer file and consumer
    /// only in its argv. Record them on the bond's serve channel, the way
    /// `bond add --token-file --consumer` does, so `skarbiec maintain` pulls
    /// exactly what the daemon pulled.
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
