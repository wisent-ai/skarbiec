use super::{process_identity, source_revision};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

/// A pipe reader stays alive until its owned input closes. Cleanup only signals
/// processes created by this test.
struct OwnedReader(std::process::Child);

impl OwnedReader {
    fn spawn() -> Self {
        Self(
            Command::new("cat")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("start pipe reader"),
        )
    }
}

impl Drop for OwnedReader {
    fn drop(&mut self) {
        if self.0.try_wait().expect("inspect owned reader").is_none() {
            self.0.kill().expect("stop owned reader");
            self.0.wait().expect("reap owned reader");
        }
    }
}

#[test]
#[ignore = "requires the authorized real qualification stage"]
fn process_identity_signals_its_target_and_refuses_a_dead_handle() {
    use std::os::unix::process::ExitStatusExt;
    let revision = source_revision();
    let mut first = OwnedReader::spawn();
    let pid = libc::pid_t::try_from(first.0.id()).unwrap();
    let mut identity = process_identity::Identity::open(pid).expect("bind actual process lifetime");
    let executable = identity
        .executable()
        .expect("inspect identity-qualified executable");
    let sent = identity.terminate();
    assert!(sent.is_ok(), "identity-qualified SIGTERM: {sent:?}");
    let exited = first.0.wait().expect("reap signaled process");
    let mut second = OwnedReader::spawn();
    let stale = identity.terminate();
    let survivor = second
        .0
        .try_wait()
        .expect("inspect unrelated owned process");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/real-tests/recovery")
        .join(format!(
            "identity-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("report.json"),
        serde_json::to_vec_pretty(&json!({
            "source_revision": revision,
            "target_pid": pid, "executable": executable,
            "target_exit": exited.to_string(), "target_signal": exited.signal(),
            "stale_identity_error": stale.as_ref().err(), "other_pid": second.0.id(),
            "other_exit": survivor.map(|status| status.to_string()),
        }))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(exited.signal(), Some(libc::SIGTERM));
    assert!(
        stale.is_err(),
        "a dead process identity must not accept a signal"
    );
    assert!(
        survivor.is_none(),
        "signaling the old identity affected another process"
    );
}
