// One HTTPS call to a provider's API signed in with a secret the vault keeps,
// for the commands that rotate a provider's token through its own API
// (rotate --with gitlab, --with cloudflare). The header carrying the secret reaches
// curl on its standard input (`-H @-`), never in an argument a process list
// shows, and a refusal names the method, the path, curl's status and the
// provider's own answer.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

/// A request: `header` is the whole header line carrying the secret, such as
/// `Authorization: Bearer <token>`; `form` fields are sent url-encoded and
/// `json` as the body, at most one of them.
pub(crate) struct Call<'a> {
    pub(crate) method: &'a str,
    pub(crate) url: &'a str,
    pub(crate) header: &'a str,
    pub(crate) form: &'a [String],
    pub(crate) json: Option<&'a Value>,
}

/// Make the call and answer the provider's JSON.
pub(crate) fn call(request: &Call) -> Result<Value> {
    let mut command = Command::new("curl");
    command.args(["-sS", "--fail-with-body", "-X", request.method, "-H", "@-"]);
    for field in request.form {
        command.args(["--data-urlencode", field]);
    }
    if let Some(body) = request.json {
        command.args([
            "-H",
            "Content-Type: application/json",
            "--data",
            &body.to_string(),
        ]);
    }
    let mut child = command
        .arg(request.url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start curl, which talks to the provider")?;
    child
        .stdin
        .take()
        .context("curl was started without a standard input")?
        .write_all(format!("{}\n", request.header).as_bytes())
        .context("hand the header to curl")?;
    let output = stado_wait::blocking(
        stado_wait::Kind::Process,
        "curl talking to a provider",
        request.url,
        || child.wait_with_output(),
    )
    .context("wait for curl")?;
    let body = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        bail!(
            "{} {} ({}): {} {}",
            request.method,
            request.url,
            output.status,
            body.trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    // A DELETE answered 204 carries no body: nothing to read, and no failure.
    if body.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&body)
        .with_context(|| format!("{} answered something that is not JSON", request.url))
}
