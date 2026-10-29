// What the GnuPG daemons serving this keyring hold in memory, and the ceiling
// above which one of them is recycled instead of kept.
//
// `gpg` starts `keyboxd` and `gpg-agent` on demand and never stops them, and
// `keyboxd` grows with every lookup it answers. After days of answering a
// vault's reads it can hold many GiB — much of it in the compressor and in
// swap — while `ps` reports a few hundred MiB resident, which is why a
// resident-size reading is not the measurement here. The host then refuses
// placement on memory pressure, and a repair that runs only on a failed read
// never runs on a healthy one.

use anyhow::{Context, Result};

use super::run_once;

/// A kibibyte, the binary unit the sizes below are declared and reported in.
/// <https://physics.nist.gov/cuu/Units/binary.html>
const KIB: u64 = 1024;
/// A mebibyte. <https://physics.nist.gov/cuu/Units/binary.html>
const MIB: u64 = 1_048_576;

/// The setting that names the ceiling, in MiB. Skarbiec holds no default:
/// the operator states it in the service environment.
pub const DAEMON_MEMORY_LIMIT_SETTING: &str = "SKARBIEC_GPG_DAEMON_MEMORY_LIMIT_MB";

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

/// The ceiling in bytes, from the setting; refused by name when it is unset.
pub fn daemon_memory_limit_bytes() -> Result<u64> {
    let raw = crate::core::env::text(DAEMON_MEMORY_LIMIT_SETTING)?.with_context(|| {
        format!(
            "{DAEMON_MEMORY_LIMIT_SETTING} is not set: the memory, in MiB, above which a GnuPG \
             daemon is replaced is the operator's to state in the Skarbiec service environment"
        )
    })?;
    let megabytes: u64 = raw.trim().parse().with_context(|| {
        format!("{DAEMON_MEMORY_LIMIT_SETTING} must be a whole number of MiB, not {raw:?}")
    })?;
    Ok(megabytes.saturating_mul(MIB))
}

pub fn human_size(bytes: u64) -> String {
    if bytes >= MIB {
        return format!("{:.1} MiB", bytes as f64 / MIB as f64);
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
        let Some(pid) = answered_pid(&answer).with_context(|| format!("ask {daemon} for its pid"))? else {
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
/// stderr: that, and only that, is `None`. A data line that holds no pid is
/// refused quoting it, because reading it as no daemon would leave a running
/// one unmeasured and never recycled.
fn answered_pid(answer: &str) -> Result<Option<u32>> {
    let Some(data) = answer.lines().find_map(|line| line.strip_prefix("D ")) else {
        return Ok(None);
    };
    let pid = data
        .trim()
        .parse()
        .with_context(|| format!("GETINFO pid answered the data line {data:?}, which is not a pid"))?;
    Ok(Some(pid))
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
    if status.is_negative() {
        return Err(std::io::Error::last_os_error()).context("proc_pid_rusage");
    }
    // SAFETY: the call succeeded, so the struct is initialised.
    Ok(unsafe { usage.assume_init() }.ri_phys_footprint)
}

#[cfg(target_os = "linux")]
fn physical_footprint(pid: u32) -> Result<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("read /proc/{pid}/status"))?;
    // The kernel writes both lines for every process (proc(5)); one that is
    // missing or unreadable is refused naming it, never measured as nothing.
    let kib = |field: &str| -> Result<u64> {
        let line = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .with_context(|| format!("/proc/{pid}/status has no {field} line"))?;
        line.trim()
            .trim_end_matches("kB")
            .trim()
            .parse::<u64>()
            .with_context(|| format!("/proc/{pid}/status states {field}{line}, which is not a number of kB"))
    };
    Ok((kib("VmRSS:")? + kib("VmSwap:")?).saturating_mul(KIB))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn physical_footprint(pid: u32) -> Result<u64> {
    anyhow::bail!("the memory footprint of pid {pid} cannot be read on this platform")
}
