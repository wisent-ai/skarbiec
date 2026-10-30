//! Retiring the predecessor units through this user's launchd domain, in
//! process: launchd is asked for each job and told to remove it over its own
//! interface (`launch_msg`), the kernel names the job's listening sockets
//! (`proc_pidinfo`), and the launch agent's arguments are read from its
//! property list here. No launchctl, lsof or plutil runs.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::ffi::{c_char, c_int, c_void, CString};
use std::path::{Path, PathBuf};

use super::plist::program_arguments;
use super::PREDECESSORS;
use crate::core::{vault::Vault, vault_path};

pub(super) fn take_over() -> BTreeSet<u16> {
    // launchd answers this process for the domain it runs in: the user's
    // own, where every predecessor's launch agent was loaded.
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
        let pid = match running_pid(label) {
            Ok(pid) => pid,
            Err(error) => {
                eprintln!(
                    "skarbiec serve: kept {label}: whether it runs could not be read: {error:#}"
                );
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
        // A removal that failed while the old job was running leaves it on
        // its ports, so such a job is kept, its plist left in place and the
        // failure named; a job with no pid has nothing to stop, so its
        // removal answer is moot.
        if let (Err(failure), Some(pid)) = (remove_job(label), pid) {
            eprintln!(
                "skarbiec serve: kept {label} (pid {pid}): launchd did not remove it: {failure:#}"
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
        eprintln!("skarbiec serve: retired {label}; this process serves its ports {inherited:?}");
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

/// launchd's interface for asking about and removing a job (`<launch.h>`).
type LaunchData = *mut c_void;
const LAUNCH_DATA_DICTIONARY: c_int = 1;
const LAUNCH_DATA_INTEGER: c_int = 4;
const LAUNCH_DATA_ERRNO: c_int = 9;

extern "C" {
    fn launch_data_alloc(kind: c_int) -> LaunchData;
    fn launch_data_free(data: LaunchData);
    fn launch_data_new_string(value: *const c_char) -> LaunchData;
    fn launch_data_dict_insert(dict: LaunchData, value: LaunchData, key: *const c_char) -> bool;
    fn launch_data_dict_lookup(dict: LaunchData, key: *const c_char) -> LaunchData;
    fn launch_data_get_type(data: LaunchData) -> c_int;
    fn launch_data_get_integer(data: LaunchData) -> i64;
    fn launch_data_get_errno(data: LaunchData) -> c_int;
    fn launch_msg(request: LaunchData) -> LaunchData;
}

/// What launchd answered one request: the reply, freed when dropped.
struct Reply(LaunchData);

impl Drop for Reply {
    fn drop(&mut self) {
        // SAFETY: the reply is the one launch_msg allocated and is freed once.
        unsafe { launch_data_free(self.0) }
    }
}

/// Send launchd `{verb: label}` and read its reply. A reply of kind errno
/// is returned as the errno, 0 when launchd says it succeeded.
fn ask_launchd(verb: &str, label: &str) -> Result<std::result::Result<Reply, c_int>> {
    let verb_c = CString::new(verb).context("a launchd verb holds a NUL")?;
    let label_c = CString::new(label).context("a job label holds a NUL")?;
    // SAFETY: each launch_data value is allocated here and handed to the
    // dictionary, which owns it; the request is freed after the message.
    let reply = unsafe {
        let request = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
        anyhow::ensure!(
            !request.is_null(),
            "launchd's request could not be allocated"
        );
        let value = launch_data_new_string(label_c.as_ptr());
        let inserted = !value.is_null() && launch_data_dict_insert(request, value, verb_c.as_ptr());
        let reply = if inserted {
            launch_msg(request)
        } else {
            std::ptr::null_mut()
        };
        launch_data_free(request);
        anyhow::ensure!(
            inserted,
            "launchd's {verb} request for {label} could not be built"
        );
        reply
    };
    if reply.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("launchd did not answer {verb} for {label}"));
    }
    let reply = Reply(reply);
    // SAFETY: the reply is a live launch_data value.
    if unsafe { launch_data_get_type(reply.0) } == LAUNCH_DATA_ERRNO {
        // SAFETY: as above; the value is of kind errno.
        return Ok(Err(unsafe { launch_data_get_errno(reply.0) }));
    }
    Ok(Ok(reply))
}

/// The pid launchd reports for a loaded, running job; none when launchd has
/// no such job loaded, or has it loaded and not running.
fn running_pid(label: &str) -> Result<Option<u32>> {
    let job = match ask_launchd("GetJob", label)? {
        Ok(job) => job,
        Err(libc::ESRCH) => return Ok(None),
        Err(errno) => {
            return Err(std::io::Error::from_raw_os_error(errno))
                .with_context(|| format!("launchd refused GetJob for {label}"))
        }
    };
    let key = CString::new("PID").context("a launchd key holds a NUL")?;
    // SAFETY: the job is a live dictionary reply; lookup returns a value it
    // owns, or null.
    let pid = unsafe { launch_data_dict_lookup(job.0, key.as_ptr()) };
    if pid.is_null() {
        return Ok(None);
    }
    // SAFETY: pid is a live value of the reply.
    if unsafe { launch_data_get_type(pid) } != LAUNCH_DATA_INTEGER {
        anyhow::bail!("launchd answered {label}'s PID as something other than a number");
    }
    // SAFETY: as above; the value is an integer.
    let pid = unsafe { launch_data_get_integer(pid) };
    u32::try_from(pid).map(Some).with_context(|| {
        format!("launchd answered {label}'s PID as {pid}, which is not a process id")
    })
}

/// Tell launchd to remove the job: it stops a running one and forgets it.
/// A job launchd does not have loaded has nothing to remove.
fn remove_job(label: &str) -> Result<()> {
    match ask_launchd("RemoveJob", label)? {
        Ok(_) | Err(0) | Err(libc::ESRCH) => Ok(()),
        Err(errno) => Err(std::io::Error::from_raw_os_error(errno))
            .with_context(|| format!("launchd refused RemoveJob for {label}")),
    }
}

/// `proc_pidfdinfo`'s answer for a socket (`struct socket_fdinfo` of
/// `<sys/proc_info.h>`) and the offsets of the fields read from it.
const SOCKET_FDINFO_SIZE: usize = 792;
const PROC_PIDFDSOCKETINFO: c_int = 3;
const SOI_FAMILY: usize = 184;
const SOI_KIND: usize = 256;
const INSI_LPORT: usize = 268;
const INSI_LADDR: usize = 312;
const TCPSI_STATE: usize = 344;
const SOCKINFO_TCP: i32 = 2;
const TSI_S_LISTEN: i32 = 1;

fn int_at(bytes: &[u8], at: usize) -> i32 {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&bytes[at..at + 4]);
    i32::from_ne_bytes(raw)
}

/// Loopback TCP ports the process is listening on, as the kernel lists its
/// sockets. A process that has exited serves none.
fn listening_ports(pid: u32) -> Result<BTreeSet<u16>> {
    let pid = c_int::try_from(pid).with_context(|| format!("pid {pid} is out of range"))?;
    let entry = std::mem::size_of::<libc::proc_fdinfo>();
    // SAFETY: a null buffer asks only for the size the list needs.
    let needed =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(BTreeSet::new());
        }
        return Err(error)
            .with_context(|| format!("the kernel would not list pid {pid}'s descriptors"));
    }
    // Room for descriptors opened since the size was asked.
    let capacity = usize::try_from(needed).context("descriptor list size")? / entry + 16;
    let mut fds: Vec<libc::proc_fdinfo> = Vec::with_capacity(capacity);
    let bytes = c_int::try_from(capacity * entry).context("descriptor list size")?;
    // SAFETY: the buffer holds `capacity` entries and the kernel writes at
    // most `bytes` into it, answering how many it wrote.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr().cast(),
            bytes,
        )
    };
    if written < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("the kernel would not list pid {pid}'s descriptors"));
    }
    // SAFETY: the kernel initialised `written` bytes of whole entries.
    unsafe { fds.set_len(usize::try_from(written).context("descriptor list size")? / entry) };
    let mut ports = BTreeSet::new();
    for fd in fds
        .iter()
        .filter(|fd| fd.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
    {
        let mut info = [0u64; SOCKET_FDINFO_SIZE / 8];
        // SAFETY: info is SOCKET_FDINFO_SIZE bytes, the size passed.
        let read = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd.proc_fd,
                PROC_PIDFDSOCKETINFO,
                info.as_mut_ptr().cast(),
                SOCKET_FDINFO_SIZE as c_int,
            )
        };
        if read <= 0 {
            // A descriptor closed since the list was read is no listener.
            continue;
        }
        anyhow::ensure!(
            read as usize == SOCKET_FDINFO_SIZE,
            "the kernel answered pid {pid}'s socket {} in {read} bytes, not the {SOCKET_FDINFO_SIZE} of the socket_fdinfo this build reads",
            fd.proc_fd
        );
        // SAFETY: info is plain bytes of that size.
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(info.as_ptr().cast::<u8>(), SOCKET_FDINFO_SIZE) };
        if int_at(bytes, SOI_KIND) != SOCKINFO_TCP || int_at(bytes, TCPSI_STATE) != TSI_S_LISTEN {
            continue;
        }
        let loopback = match int_at(bytes, SOI_FAMILY) {
            libc::AF_INET => bytes[INSI_LADDR + 12] == 127,
            libc::AF_INET6 => {
                let mut address = [0u8; 16];
                address.copy_from_slice(&bytes[INSI_LADDR..INSI_LADDR + 16]);
                std::net::Ipv6Addr::from(address).is_loopback()
            }
            _ => false,
        };
        if loopback {
            // The kernel keeps the port in network byte order.
            ports.insert(u16::from_be(int_at(bytes, INSI_LPORT) as u16));
        }
    }
    Ok(ports)
}

/// The removed `sync-daemon` carried its bond's bearer file and consumer
/// only in its argv. Record them on the bond's serve channel, the way
/// `bond add --token-file --consumer` does, so `skarbiec maintain` pulls
/// exactly what the daemon pulled. A unit that names one of them not is
/// refused naming the missing flag, never given a consumer of our choice.
fn adopt_replica_bond(arguments: &[String]) -> Result<()> {
    let value = |flag: &str| {
        let mut words = arguments.iter();
        words.find(|argument| *argument == flag)?;
        words.next().cloned()
    };
    let name = value("--bond").context("the unit names no --bond")?;
    let token_file = value("--token-file").context("the unit names no --token-file")?;
    let consumer = value("--consumer").context("the unit names no --consumer")?;
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
