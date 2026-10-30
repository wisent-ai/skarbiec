// One HTTPS call to a provider's API signed in with a secret the vault keeps,
// for the commands that rotate a provider's token through its own API
// (rotate --with gitlab, --with cloudflare). The call is made in process
// over Skarbiec's own TLS client, so the header carrying the secret is in no
// argument a process list shows, and a refusal names the method, the
// address, the provider's status and its own answer.

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// A request: `header` is the whole header line carrying the secret, such as
/// `Authorization: Bearer <token>`; `form` fields (`name=value`) are sent
/// url-encoded and `json` as the body, at most one of them.
pub(crate) struct Call<'a> {
    pub(crate) method: &'a str,
    pub(crate) url: &'a str,
    pub(crate) header: &'a str,
    pub(crate) form: &'a [String],
    pub(crate) json: Option<&'a Value>,
}

/// Make the call and answer the provider's JSON.
pub(crate) fn call(request: &Call) -> Result<Value> {
    let Some((name, value)) = request.header.split_once(':') else {
        bail!("the header for {} is not `Name: value`", request.url);
    };
    let mut headers = vec![(name.trim(), value.trim())];
    let body = match (request.form, request.json) {
        ([], None) => None,
        ([], Some(json)) => {
            headers.push(("Content-Type", "application/json"));
            Some(json.to_string().into_bytes())
        }
        (fields, None) => {
            let mut form = form_urlencoded::Serializer::new(String::new());
            for field in fields {
                let (name, value) = field.split_once('=').unwrap_or((field, ""));
                form.append_pair(name, value);
            }
            headers.push(("Content-Type", "application/x-www-form-urlencoded"));
            Some(form.finish().into_bytes())
        }
        (_, Some(_)) => bail!(
            "a call to {} names both form fields and a JSON body; a request carries one",
            request.url
        ),
    };
    let what = "a provider's API";
    let reply =
        crate::net::https::exchange(request.method, request.url, &headers, body.as_deref(), what)?;
    crate::net::https::ensure_success(&reply, request.method, request.url, what)?;
    let body = String::from_utf8_lossy(&reply.body);
    // A DELETE answered 204 carries no body: nothing to read, and no failure.
    if body.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&body)
        .with_context(|| format!("{} answered something that is not JSON", request.url))
}
