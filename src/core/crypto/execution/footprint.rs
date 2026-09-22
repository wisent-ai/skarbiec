// What the GnuPG daemons serving this keyring hold in memory, and the ceiling
// above which one of them is recycled instead of kept.
//
// `gpg` starts `keyboxd` and `gpg-agent` on demand and never stops them, and
// `keyboxd` grows with every lookup it answers. On charless-mac-mini it had
// answered a vault's reads for twelve days and held 15 GiB — 3.7 GiB of it in
// the compressor and 6.4 GiB in swap — while `ps` reported 327 MiB resident,
// which is why a resident-size reading is not the measurement here. The host
// refused placement on memory pressure, and the only repair that existed
// (`recover-daemons`) ran on a failed read, never on a healthy one.

use anyhow::{Context, Result};

use super::run_once;

/// Kilobytes and mebibytes as the sizes below are declared and reported.
const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

/// The setting that names the ceiling, in MiB, and the ceiling used when it
/// is unset. A healthy `keyboxd` serving a few hundred items holds well under
/// 300 MiB; a whole gibibyte leaves room for a large keyring while still
/// catching the growth that took a 16 GiB host down.
pub const DAEMON_MEMORY_LIMIT_SETTING: &str = "SKARBIEC_GPG_DAEMON_MEMORY_LIMIT_MB";
const DEFAULT_DAEMON_MEMORY_LIMIT_MB: u64 = 1024;

/// One live GnuPG daemon of this keyring and what it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonFootprint {
    pub daemon: &'static str,
    pub pid: u32,
    /// Physical footprint: resident, compressed and swapped pages together,
    /// which is what the host's memory pressure is made of.
    pub bytes: u64,
}

impl DaemonFootprint {
    pub fn describe(&self) -> String {
        format!(
            "{} {} (pid {})",
            self.daemon,
            human_size(self.bytes),
            self.pid
        )
    }
}

/// The ceiling in bytes, from the setting or its default.
pub fn daemon_memory_limit_bytes() -> u64 {
    std::env::var(DAEMON_MEMORY_LIMIT_SETTING)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_DAEMON_MEMORY_LIMIT_MB)
        .saturating_mul(MIB)
}

pub fn human_size(bytes: u64) -> String {
    if bytes >= MIB {
        let whole = bytes / MIB;
        let tenths = (bytes % MIB) * 10 / MIB;
        return format!("{whole}.{tenths} MiB");
    }
    format!("{} KiB", bytes / KIB)
}

/// Every GnuPG daemon of this keyring that is running, with its footprint.
///
/// Each daemon is asked for its own pid over GnuPG's control surface, with
/// autostart off, so a daemon that is not running is reported absent rather
/// than started to be measured. The pid is exact for this `GNUPGHOME`: a
/// process-table search by name would find another account's or another
/// fixture's daemons too.
pub fn daemon_footprints() -> Result<Vec<DaemonFootprint>> {
    let mut footprints = Vec::new();
    for (daemon, args) in [
        (
            "keyboxd",
            &["--no-autostart", "--keyboxd", "GETINFO pid", "/bye"][..],
        ),
        ("gpg-agent", &["--no-autostart", "GETINFO pid", "/bye"][..]),
    ] {
        let answer = run_once("gpg-connect-agent", args, None)
            .with_context(|| format!("ask {daemon} for its pid"))?;
        let Some(pid) = answered_pid(&answer) else {
            continue;
        };
        let bytes = physical_footprint(pid)
            .with_context(|| format!("read the memory footprint of {daemon} (pid {pid})"))?;
        footprints.push(DaemonFootprint { daemon, pid, bytes });
    }
    Ok(footprints)
}

/// The `D <pid>` data line a running daemon answers `GETINFO pid` with. A
/// daemon that is not running answers `OK` and nothing else, and says so on
/// stderr.
fn answered_pid(answer: &str) -> Option<u32> {
    answer
        .lines()
        .filter_map(|line| line.strip_prefix("D "))
        .find_map(|data| data.trim().parse().ok())
}

#[cfg(target_os = "macos")]
fn physical_footprint(pid: u32) -> Result<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage_info_v0>::uninit();
    // SAFETY: `RUSAGE_INFO_V0` names the exact struct the buffer holds, the
    // kernel writes only that struct, and the value is read only after the
    // call reported success.
    let status = unsafe {
        libc::proc_pid_rusage(
            pid as libc::c_int,
            libc::RUSAGE_INFO_V0,
            usage.as_mut_ptr().cast::<libc::rusage_info_t>(),
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error()).context("proc_pid_rusage");
    }
    // SAFETY: the call succeeded, so the struct is initialised.
    Ok(unsafe { usage.assume_init() }.ri_phys_footprint)
}

#[cfg(target_os = "linux")]
fn physical_footprint(pid: u32) -> Result<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("read /proc/{pid}/status"))?;
    let kib = |field: &str| -> u64 {
        status
            .lines()
            .filter_map(|line| line.strip_prefix(field))
            .find_map(|rest| {
                rest.trim()
                    .trim_end_matches("kB")
                    .trim()
                    .parse::<u64>()
                    .ok()
            })
            .unwrap_or_default()
    };
    Ok((kib("VmRSS:") + kib("VmSwap:")).saturating_mul(KIB))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn physical_footprint(pid: u32) -> Result<u64> {
    anyhow::bail!("the memory footprint of pid {pid} cannot be read on this platform")
}
