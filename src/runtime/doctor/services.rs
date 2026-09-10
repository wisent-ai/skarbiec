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
                check(
                    "endpoint",
                    FAIL,
                    format!("nothing answers {endpoint}, declared by {forward}"),
                )
            }
        }
        Err(error) => check("endpoint", NOT_CONFIGURED, error.to_string()),
    }
}

/// Write-once receipts, which nobody configures by default.
pub(super) fn worm_check() -> Value {
    let directory = std::env::var("SKARBIEC_WORM_RECEIPT_DIR").unwrap_or_default();
    let checkpoint = std::env::var("SKARBIEC_WORM_CHECKPOINT").unwrap_or_default();
    if directory.trim().is_empty() || checkpoint.trim().is_empty() {
        return check(
            "worm",
            NOT_CONFIGURED,
            "set SKARBIEC_WORM_RECEIPT_DIR and SKARBIEC_WORM_CHECKPOINT to enable write-once receipts".to_string(),
        );
    }
    let missing: Vec<&str> = [directory.as_str(), checkpoint.as_str()]
        .into_iter()
        .filter(|path| !std::path::Path::new(path).exists())
        .collect();
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
