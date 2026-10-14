// The parts an operator configures outside the vault: the canonical endpoint
// this host resolves, and the write-once receipt store when there is one.

use serde_json::Value;

use crate::credential;

use super::{check, FAIL, NOT_CONFIGURED, PASS};

/// The canonical endpoint, resolved from its file and probed with a connect.
pub(super) fn endpoint_check() -> Value {
    match credential::canonical_endpoint_report() {
        Ok(report) => {
            let endpoint = report
                .get("endpoint")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let forward = report
                .get("forward")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let answering = report
                .get("answering")
                .and_then(Value::as_bool)
                .unwrap_or_default();
            if answering {
                check(
                    "endpoint",
                    PASS,
                    format!("{endpoint}, declared by {forward}"),
                )
            } else {
                let cause = match report.get("connect_error").and_then(Value::as_str) {
                    Some(error) => format!(" ({error})"),
                    None => String::new(),
                };
                check(
                    "endpoint",
                    FAIL,
                    format!("nothing answers {endpoint}{cause}, declared by {forward}"),
                )
            }
        }
        Err(error) => check("endpoint", NOT_CONFIGURED, error.to_string()),
    }
}

/// Write-once receipts, which nobody configures by default.
pub(super) fn worm_check() -> Value {
    // A value that is not text fails the check by name: read as unset, the
    // doctor reported receipts as never configured while they were.
    let read = |name: &str| match std::env::var(name) {
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotPresent) => Ok(String::new()),
        Err(error) => Err(format!("{name} is set but cannot be read: {error}")),
    };
    let (directory, checkpoint) = match (
        read("SKARBIEC_WORM_RECEIPT_DIR"),
        read("SKARBIEC_WORM_CHECKPOINT"),
    ) {
        (Ok(directory), Ok(checkpoint)) => (directory, checkpoint),
        (Err(cause), _) | (_, Err(cause)) => return check("worm", FAIL, cause),
    };
    if directory.trim().is_empty() || checkpoint.trim().is_empty() {
        return check(
            "worm",
            NOT_CONFIGURED,
            "set SKARBIEC_WORM_RECEIPT_DIR and SKARBIEC_WORM_CHECKPOINT to enable write-once receipts".to_string(),
        );
    }
    let mut missing: Vec<&str> = Vec::new();
    for path in [directory.as_str(), checkpoint.as_str()] {
        match crate::core::is_present(std::path::Path::new(path), "write-once receipt path") {
            Ok(true) => {}
            Ok(false) => missing.push(path),
            // A receipt path that cannot be examined is the failure with its
            // cause, not one reported as absent.
            Err(error) => return check("worm", FAIL, format!("{error:#}")),
        }
    }
    if missing.is_empty() {
        check("worm", PASS, format!("receipts in {directory}"))
    } else {
        check(
            "worm",
            FAIL,
            format!("configured but absent: {}", missing.join(", ")),
        )
    }
}
