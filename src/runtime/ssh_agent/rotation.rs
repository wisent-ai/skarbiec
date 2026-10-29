// After rotate --with ssh the running ssh-agent may still hold the retired key:
// git push and ssh keep offering it, and every place that dropped it refuses
// them, far from the rotation that caused it. When the agent this process
// would use (SSH_AUTH_SOCK) holds the retired key, the new one is loaded from
// the vault the way `ssh add <id>` loads it, and only then is the retired one
// deleted from the agent, by its public key. An agent that does not hold the
// retired key is left alone. The rotation stands whatever this answers.

use serde_json::{json, Value};
use std::process::Command;

/// The type and key of a public key line, without its comment.
fn bare(key: &str) -> Option<String> {
    let words: Vec<&str> = key.split_whitespace().collect();
    match words.as_slice() {
        [kind, body, ..] => Some(format!("{kind} {body}")),
        _ => None,
    }
}

/// Swap the retired key for `id`'s new one in the running agent, answering
/// whether it did, why not, or what failed.
pub(in crate::runtime) fn follow_rotation(id: &str, retired: &str) -> Value {
    let Some(socket) = crate::core::env::path("SSH_AUTH_SOCK") else {
        return json!({"swapped": false, "reason": "no ssh-agent is named by SSH_AUTH_SOCK here"});
    };
    let Some(old) = bare(retired) else {
        return json!({"swapped": false, "error": "the retired key is not an SSH public key line"});
    };
    let listed = match stado_wait::output(Command::new("ssh-add").arg("-L").env("SSH_AUTH_SOCK", &socket)) {
        Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
        Err(error) => return json!({"swapped": false, "error": format!("ssh-add -L could not run: {error:#}")}),
    };
    if !listed.lines().any(|line| bare(line).as_deref() == Some(old.as_str())) {
        return json!({"swapped": false, "reason": "the agent does not hold the retired key"});
    }
    if let Err(error) = super::add(id, None, Some(&socket.display().to_string())) {
        return json!({"swapped": false, "error": format!("the new key could not be loaded, so the retired one was left: {error:#}")});
    }
    let work = match crate::runtime::keygen::workspace(&crate::core::vault_path()) {
        Ok(work) => work,
        Err(error) => return json!({"swapped": false, "added_new": true, "error": format!("{error:#}"), "remove_with": "ssh-add -d <the retired public key file>"}),
    };
    let file = work.0.join("retired.pub");
    if let Err(error) = crate::core::vault::atomic_write(&file, format!("{old}\n").as_bytes()) {
        return json!({"swapped": false, "added_new": true, "error": format!("write the retired public key to {}: {error:#}", file.display())});
    }
    match stado_wait::output(Command::new("ssh-add").arg("-d").arg(&file).env("SSH_AUTH_SOCK", &socket)) {
        Ok(output) if output.status.success() => json!({"swapped": true, "agent": socket}),
        Ok(output) => json!({
            "swapped": false,
            "added_new": true,
            "error": format!("ssh-add -d ({}): {}", output.status, String::from_utf8_lossy(&output.stderr).trim()),
        }),
        Err(error) => json!({"swapped": false, "added_new": true, "error": format!("ssh-add -d could not run: {error:#}")}),
    }
}
