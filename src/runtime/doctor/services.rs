// The parts an operator configures outside the vault: the canonical endpoint
// this host resolves, and the write-once receipt store when there is one.

use serde_json::Value;

use crate::credential;

use super::{check, FAIL, NOT_CONFIGURED, PASS};

/// The canonical endpoint, resolved from its file and probed with a connect.
pub(super) fn endpoint_check() -> Value {
    match credential::canonical_endpoint_report() {
        Ok(report) => {
            // The report always carries all three; one that does not is a
            // fault of the report, said whole, not an endpoint named "".
            let (Some(endpoint), Some(forward), Some(answering)) = (
                report.get("endpoint").and_then(Value::as_str),
                report.get("forward").and_then(Value::as_str),
                report.get("answering").and_then(Value::as_bool),
            ) else {
                return check(
                    "endpoint",
                    FAIL,
                    format!("the endpoint report lacks endpoint, forward or answering: {report}"),
                );
            };
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
    // Paths are read as the OS hands them over (`core::env::path`), so a
    // receipt path that is not UTF-8 is checked like any other instead of
    // failing as unreadable text.
    let declared = (
        crate::core::env::path("SKARBIEC_WORM_RECEIPT_DIR"),
        crate::core::env::path("SKARBIEC_WORM_CHECKPOINT"),
    );
    let (Some(directory), Some(checkpoint)) = declared else {
        return check(
            "worm",
            NOT_CONFIGURED,
            "set SKARBIEC_WORM_RECEIPT_DIR and SKARBIEC_WORM_CHECKPOINT to enable write-once receipts".to_string(),
        );
    };
    let mut missing = Vec::new();
    for path in [&directory, &checkpoint] {
        match crate::core::is_present(path, "write-once receipt path") {
            Ok(true) => {}
            Ok(false) => missing.push(path.display().to_string()),
            // A receipt path that cannot be examined is the failure with its
            // cause, not one reported as absent.
            Err(error) => return check("worm", FAIL, format!("{error:#}")),
        }
    }
    if missing.is_empty() {
        check("worm", PASS, format!("receipts in {}", directory.display()))
    } else {
        check(
            "worm",
            FAIL,
            format!("configured but absent: {}", missing.join(", ")),
        )
    }
}
