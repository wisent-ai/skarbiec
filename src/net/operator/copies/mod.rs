// The operator routes that keep and check copies of the vault file: `backup
// <directory>` and `backup check <file> [--open]`. Both name paths on the
// machine serving this API, so they run there and are never forwarded, and a
// relative path is refused, because it would resolve against a working
// directory nobody sees. `routes` asks this table before its own.

use anyhow::{bail, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use super::calls::{flags, runtime, text};

mod helpers;
mod packages;
pub(super) use helpers::{is_host_local as is_helper_host_local, is_mutation as is_helper_mutation};
pub(super) use packages::{is_host_local as is_package_host_local, is_mutation as is_package_mutation};

fn absolute(parsed: &Value, key: &str) -> Result<String> {
    let path = text(parsed, key)?;
    if !Path::new(&path).is_absolute() {
        bail!("{key} must be an absolute path on this machine; got {path}");
    }
    Ok(path)
}

pub(super) fn answer(path: &str, parsed: &Value) -> Result<Option<Value>> {
    let answer = match path {
        "/v1/operator/backup" => runtime("backup", &flags(parsed, &[]), &[absolute(parsed, "directory")?]),
        "/v1/operator/backup/check" => runtime(
            "backup",
            &flags(parsed, &["open"]),
            &["check".to_string(), absolute(parsed, "file")?],
        ),
        // Both files' envelopes, nothing decrypted.
        "/v1/operator/backup/diff" => runtime(
            "backup",
            &flags(parsed, &[]),
            &["diff".to_string(), absolute(parsed, "file")?],
        ),
        // The public key file is on this machine; the certificate, public,
        // comes back in the answer.
        "/v1/operator/ssh-sign" => runtime(
            "ssh",
            &flags(parsed, &["identity", "principals", "validity", "host"]),
            &["sign".to_string(), text(parsed, "ca")?, absolute(parsed, "public_key_file")?],
        ),
        // Without `yes` it says what the copy holds and what would be lost;
        // the desktop sends `yes` only from its own confirmation.
        "/v1/operator/backup/restore" => runtime(
            "backup",
            &flags(parsed, &["yes"]),
            &["restore".to_string(), absolute(parsed, "file")?],
        ),
        // With directory, every maintain pass here keeps a rolling copy
        // there; without, the answer names the directory now scheduled.
        "/v1/operator/backup/schedule" => match super::calls::optional(parsed, "directory") {
            Some(_) => runtime("backup", &flags(parsed, &[]), &["schedule".to_string(), absolute(parsed, "directory")?]),
            None => runtime("backup", &flags(parsed, &[]), &["schedule".to_string()]),
        },
        "/v1/operator/backup/unschedule" => runtime("backup", &flags(parsed, &[]), &["unschedule".to_string()]),
        // The alert setting sits beside this host's vault file; the answers
        // name the item and field, never the webhook address.
        "/v1/operator/alert/set" => runtime("alert", &flags(parsed, &["field"]), &["set".to_string(), text(parsed, "id")?]),
        "/v1/operator/alert/status" => runtime("alert", &flags(parsed, &[]), &["status".to_string()]),
        "/v1/operator/alert/test" => runtime("alert", &flags(parsed, &[]), &["test".to_string()]),
        "/v1/operator/alert/unset" => runtime("alert", &flags(parsed, &[]), &["unset".to_string()]),
        // `doctor --alert`: the report, and the failed checks posted.
        "/v1/operator/doctor/alert" => crate::runtime::doctor::report_alerting(None),
        // The filled file is written here, owner-only; the answer names the
        // references and never carries a value.
        "/v1/operator/inject" => runtime(
            "inject",
            &flags(parsed, &["replace"]),
            &[absolute(parsed, "template")?, absolute(parsed, "out")?],
        ),
        // The .env and the bindings file are on this machine; without yes
        // the answer lists what would be stored, and never carries a value.
        "/v1/operator/env-import" => {
            let mut given = flags(parsed, &["prefix", "tags", "replace", "yes"]);
            if super::calls::optional(parsed, "bindings").is_some() {
                given.insert("bindings".to_string(), absolute(parsed, "bindings")?);
            }
            runtime("env", &given, &["import".to_string(), absolute(parsed, "source")?])
        }
        // The files compared are on this machine; the answer names where a
        // copy sits, never the value.
        "/v1/operator/scan" => runtime("scan", &flags(parsed, &["fields", "min-length"]), &[absolute(parsed, "path")?]),
        "/v1/operator/scan-history" => {
            let mut given = flags(parsed, &["fields", "min-length"]);
            given.insert("history".to_string(), "true".to_string());
            runtime("scan", &given, &[absolute(parsed, "repo")?])
        }
        // The target's CLI and its sign-in, and the bindings file, are on
        // this machine; without yes the answer only names what it would set.
        // target is github or kubernetes, place owner/repo or namespace/name.
        "/v1/operator/ci-secrets" => runtime(
            "ci",
            &HashMap::from_iter(
                flags(parsed, &["environment", "context", "yes"])
                    .into_iter()
                    .chain([("env-from".to_string(), absolute(parsed, "bindings")?)]),
            ),
            &["set".to_string(), text(parsed, "target")?, text(parsed, "place")?],
        ),
        // The same, kept: set now and again by every maintain pass here once
        // an item they name changes.
        "/v1/operator/ci-secrets/keep" => runtime(
            "ci",
            &HashMap::from_iter(
                flags(parsed, &["environment", "context"])
                    .into_iter()
                    .chain([("env-from".to_string(), absolute(parsed, "bindings")?)]),
            ),
            &["keep".to_string(), text(parsed, "target")?, text(parsed, "place")?],
        ),
        "/v1/operator/ci-secrets/kept" => runtime("ci", &flags(parsed, &[]), &["kept".to_string()]),
        "/v1/operator/ci-secrets/forget" => runtime(
            "ci",
            &flags(parsed, &[]),
            &["forget".to_string(), text(parsed, "target")?, text(parsed, "place")?],
        ),
        // A repository on this machine: its pre-commit hook runs scan
        // --refuse over what a commit adds, or no longer does.
        "/v1/operator/git-hook/install" => runtime(
            "hook",
            &flags(parsed, &["fields", "min-length", "replace"]),
            &["install".to_string(), absolute(parsed, "repo")?],
        ),
        "/v1/operator/git-hook/status" => {
            runtime("hook", &flags(parsed, &[]), &["status".to_string(), absolute(parsed, "repo")?])
        }
        "/v1/operator/git-hook/uninstall" => {
            runtime("hook", &flags(parsed, &[]), &["uninstall".to_string(), absolute(parsed, "repo")?])
        }
        // git's configuration is this machine's; the answer names the key and
        // the item, never a private key.
        "/v1/operator/git-sign/setup" => {
            runtime("signing", &flags(parsed, &["repo", "github"]), &["setup".to_string(), text(parsed, "id")?])
        }
        "/v1/operator/git-sign/status" => runtime("signing", &flags(parsed, &["repo"]), &["status".to_string()]),
        "/v1/operator/git-sign/unset" => runtime("signing", &flags(parsed, &["repo"]), &["unset".to_string()]),
        _ => match helpers::answer(path, parsed)? {
            Some(answer) => return Ok(Some(answer)),
            None => return packages::answer(path, parsed),
        },
    };
    answer.map(Some)
}
