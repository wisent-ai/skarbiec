//! Bind executable inspection and SIGTERM to a process lifetime, not a PID.
use std::path::PathBuf;

#[cfg(target_os = "macos")]
mod platform {
    use super::PathBuf;
    use mach2::{kern_return::KERN_SUCCESS, mach_port::mach_port_deallocate,
        message::audit_token_t, port::MACH_PORT_NULL, task::task_info,
        task_info::{TASK_AUDIT_TOKEN, TASK_AUDIT_TOKEN_COUNT},
        traps::{mach_task_self, task_name_for_pid}};
    use std::{mem::MaybeUninit, os::unix::ffi::OsStrExt};

    // libproc.h: both operations use the same audit identity. The kernel
    // retains proc_find_ident's target reference while delivering the signal.
    extern "C" {
        fn proc_pidpath_audittoken(token: *mut audit_token_t, buffer: *mut libc::c_void,
            size: u32) -> libc::c_int;
        fn proc_signal_with_audittoken(token: *mut audit_token_t, signal: libc::c_int) -> libc::c_int;
    }

    pub(crate) struct Identity(audit_token_t);

    impl Identity {
        pub(crate) fn open(pid: libc::pid_t) -> Result<Self, String> {
            let mut task = MACH_PORT_NULL;
            // SAFETY: writable output storage; the name port is not task control.
            let status = unsafe { task_name_for_pid(mach_task_self(), pid, &mut task) };
            if status != KERN_SUCCESS {
                return Err(format!("task_name_for_pid({pid}) refused identity: Mach error {status}"));
            }
            let mut token = MaybeUninit::<audit_token_t>::uninit();
            let mut count = TASK_AUDIT_TOKEN_COUNT;
            // SAFETY: buffer and count describe one complete audit token.
            let status = unsafe { task_info(task, TASK_AUDIT_TOKEN, token.as_mut_ptr().cast(), &mut count) };
            // SAFETY: releases our acquired send right, not the target process.
            let released = unsafe { mach_port_deallocate(mach_task_self(), task) };
            if status != KERN_SUCCESS {
                return Err(format!("task_info({pid}, TASK_AUDIT_TOKEN) failed: Mach error {status}; port release {released}"));
            }
            if released != KERN_SUCCESS {
                return Err(format!("mach_port_deallocate for pid {pid} failed: Mach error {released}"));
            }
            if count != TASK_AUDIT_TOKEN_COUNT {
                return Err(format!("task_info({pid}) returned {count} token words, expected {TASK_AUDIT_TOKEN_COUNT}"));
            }
            // SAFETY: success and the exact output count establish initialization.
            Ok(Self(unsafe { token.assume_init() }))
        }

        pub(crate) fn executable(&mut self) -> Result<PathBuf, String> {
            let mut buffer = [MaybeUninit::<u8>::uninit(); libc::PROC_PIDPATHINFO_MAXSIZE as usize];
            // SAFETY: writable storage sized by the SDK. libproc returns strlen
            // of the initialized path, excluding its terminating NUL.
            let length = unsafe { proc_pidpath_audittoken(&mut self.0, buffer.as_mut_ptr().cast(),
                u32::try_from(buffer.len()).expect("SDK path limit fits libproc size")) };
            if !length.is_positive() {
                return Err(format!("proc_pidpath_audittoken failed: {}", std::io::Error::last_os_error()));
            }
            let length = usize::try_from(length).map_err(|error| format!("invalid path length: {error}"))?;
            if length >= buffer.len() {
                return Err(format!("proc_pidpath_audittoken path length {length} exceeds its buffer"));
            }
            // SAFETY: only the successful call's initialized path bytes are read.
            let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), length) };
            Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
        }

        pub(crate) fn terminate(&mut self) -> Result<(), String> {
            // SAFETY: initialized token, unchanged since executable inspection.
            let status = unsafe { proc_signal_with_audittoken(&mut self.0, libc::SIGTERM) };
            if status.is_negative() {
                Err(format!("proc_signal_with_audittoken(SIGTERM) failed: {}", std::io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::PathBuf;
    use rustix::{fd::OwnedFd, process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal}};

    pub(crate) struct Identity {
        descriptor: OwnedFd,
        pid: libc::pid_t,
    }

    impl Identity {
        pub(crate) fn open(pid: libc::pid_t) -> Result<Self, String> {
            let target = Pid::from_raw(pid).filter(|_| pid.is_positive())
                .ok_or_else(|| format!("pidfd_open requires a positive process id, got {pid}"))?;
            let descriptor = pidfd_open(target, PidfdFlags::empty())
                .map_err(|error| format!("pidfd_open({pid}) failed: {error}"))?;
            Ok(Self { descriptor, pid })
        }

        pub(crate) fn executable(&mut self) -> Result<PathBuf, String> {
            // Acquire pidfd BEFORE inspecting /proc. If the process exits and
            // the PID is reused, signaling the old handle fails with ESRCH.
            std::fs::read_link(PathBuf::from("/proc").join(self.pid.to_string()).join("exe"))
                .map_err(|error| format!("reading executable for pid {} failed: {error}", self.pid))
        }

        pub(crate) fn terminate(&mut self) -> Result<(), String> {
            pidfd_send_signal(&self.descriptor, Signal::TERM)
                .map_err(|error| format!("pidfd_send_signal(SIGTERM) failed: {error}"))
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) use platform::Identity;
