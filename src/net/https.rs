//! One HTTP/1.1 exchange with a service off this host, over Skarbiec's own
//! TLS 1.3 client (skarbiec-crypto's `tls::handshake`), in process: the
//! public lists Skarbiec reads (Have I Been Pwned, the 2FA Directory,
//! Password Manager Resources), the providers a rotation calls, and the
//! alert webhook. No curl is started.
//!
//! The server's chain is checked against the trust anchors of this host:
//! the PEM bundle SSL_CERT_FILE names, else the first of the bundles the
//! operating systems keep (macOS /etc/ssl/cert.pem, Debian and Ubuntu
//! /etc/ssl/certs/ca-certificates.crt, Fedora and RHEL
//! /etc/pki/tls/certs/ca-bundle.crt). A server that speaks only TLS 1.2 is
//! refused naming that, as is one whose chain does not lead to an anchor.
//! An http:// address is dialled only on this host's loopback interface.

use anyhow::{bail, Context, Result};
use skarbiec_crypto::tls::handshake::{connect, Connection};
use skarbiec_crypto::x509::Anchor;
use std::io::{BufReader, Read};
use std::net::TcpStream;
use std::sync::OnceLock;

use super::loopback::{self, Reply};

/// The trust bundles the operating systems keep, looked for in this order
/// when SSL_CERT_FILE names none.
const BUNDLES: [&str; 3] = [
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
];

/// The anchors of this host, read once.
fn anchors() -> Result<&'static [Anchor]> {
    static ANCHORS: OnceLock<std::result::Result<Vec<Anchor>, String>> = OnceLock::new();
    ANCHORS
        .get_or_init(|| load_anchors().map_err(|error| format!("{error:#}")))
        .as_deref()
        .map_err(|error| anyhow::anyhow!("{error}"))
}

fn load_anchors() -> Result<Vec<Anchor>> {
    let (path, text) = match crate::core::env::path("SSL_CERT_FILE") {
        Some(path) => {
            let text = std::fs::read_to_string(&path).with_context(|| {
                format!(
                    "read the trust bundle SSL_CERT_FILE names, {}; name a readable PEM bundle \
                     or unset it to use this host's own",
                    path.display()
                )
            })?;
            (path, text)
        }
        None => {
            let mut found = None;
            for candidate in BUNDLES {
                let path = std::path::PathBuf::from(candidate);
                if let Some(text) = crate::core::read_present(&path, "a trust bundle")? {
                    found = Some((path, text));
                    break;
                }
            }
            found.with_context(|| {
                format!(
                    "this host keeps no trust bundle at {}, so no server off this host can be \
                     trusted; install the system's CA certificates (ca-certificates) or name a \
                     PEM bundle with SSL_CERT_FILE",
                    BUNDLES.join(", ")
                )
            })?
        }
    };
    let mut anchors = Vec::new();
    for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let Some((body, _)) = block.split_once("-----END CERTIFICATE-----") else {
            continue;
        };
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let Ok(der) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, compact)
        else {
            continue;
        };
        // A root whose key this client cannot use (P-521, DSA) cannot
        // anchor any chain it checks, so it is left out rather than refused.
        if let Ok(anchor) = Anchor::from_der(&der) {
            anchors.push(anchor);
        }
    }
    if anchors.is_empty() {
        bail!(
            "the trust bundle {} holds no certificate this client can use as a root; name a PEM \
             bundle of CA certificates with SSL_CERT_FILE",
            path.display()
        );
    }
    Ok(anchors)
}

/// An https:// URL: the host, the port, and the path with its query.
fn split(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("https://")
        .with_context(|| format!("{url} is not an https:// address"))?;
    let (authority, path) = match rest.find(['/', '?']) {
        Some(at) if rest[at..].starts_with('/') => (&rest[..at], rest[at..].to_string()),
        Some(at) => (&rest[..at], format!("/{}", &rest[at..])),
        None => (rest, "/".to_string()),
    };
    if authority.contains('@') {
        bail!("{url} carries credentials in its address; send them as a header instead");
    }
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => {
            let (host, after) = bracketed
                .split_once(']')
                .with_context(|| format!("{url} opens an IPv6 address it does not close"))?;
            (host, after.strip_prefix(':'))
        }
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    let port = match port {
        Some(port) => port
            .parse()
            .with_context(|| format!("{url} names port {port}, which is not a port number"))?,
        None => 443,
    };
    if host.is_empty() {
        bail!("{url} names no host");
    }
    Ok((host.to_string(), port, path))
}

/// The seconds since 1970 a certificate's validity is checked at.
fn now() -> Result<i64> {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("this host's clock is before 1970, so no certificate's validity can be checked")?;
    i64::try_from(since.as_secs()).context("this host's clock is past what a certificate states")
}

/// Application data off a connection, as a byte stream.
struct Plain<'a>(&'a mut Connection<TcpStream>, Vec<u8>, usize);

impl Read for Plain<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.2 == self.1.len() {
            self.1 = self
                .0
                .receive()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            self.2 = 0;
        }
        let n = out.len().min(self.1.len() - self.2);
        out[..n].copy_from_slice(&self.1[self.2..self.2 + n]);
        self.2 += n;
        Ok(n)
    }
}

/// Send one request to `url` and read its reply, whatever its status.
/// `headers` follow Host; the body, when there is one, is sent with its
/// length. `what` names the exchange in every error.
pub(crate) fn exchange(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    what: &str,
) -> Result<Reply> {
    if let Some(rest) = url.strip_prefix("http://") {
        let address = loopback::loopback_authority(url)?;
        let path = rest
            .find('/')
            .map_or("/".to_string(), |at| rest[at..].to_string());
        return loopback::exchange(address, method, &path, headers, body, what);
    }
    let (host, port, path) = split(url).with_context(|| format!("{what}: {url}"))?;
    let authority = match port {
        443 => host.clone(),
        port => format!("{host}:{port}"),
    };
    let head = loopback::request_head(method, &path, &authority, headers, body, what)?;
    let anchors = anchors().with_context(|| format!("{what}: {url}"))?;
    let now = now()?;
    stado_wait::blocking(
        stado_wait::Kind::Network,
        what,
        &authority,
        || -> std::io::Result<Reply> {
            let stream = TcpStream::connect((host.as_str(), port))?;
            let mut connection = connect(stream, &host, anchors, now, &["http/1.1"])
                .map_err(std::io::Error::other)?;
            let mut request = head.as_bytes().to_vec();
            if let Some(body) = body {
                request.extend_from_slice(body);
            }
            connection.send(&request).map_err(std::io::Error::other)?;
            let reply =
                loopback::read_reply(BufReader::new(Plain(&mut connection, Vec::new(), 0)))?;
            // The reply is whole; a failed close_notify changes nothing read.
            if let Err(error) = connection.close() {
                eprintln!(
                    "{what}: the reply was read, and closing the TLS connection failed: {error}"
                );
            }
            Ok(reply)
        },
    )
    .with_context(|| format!("{what}: {method} {url}"))
}

/// GET `url` and answer its body, refusing any status but 2xx with the
/// status and what the server said.
pub(crate) fn get(url: &str, headers: &[(&str, &str)], what: &str) -> Result<Vec<u8>> {
    let reply = exchange("GET", url, headers, None, what)?;
    ensure_success(&reply, "GET", url, what)?;
    Ok(reply.body)
}

/// Refuse a reply whose status is not 2xx, naming it and the body's start.
pub(crate) fn ensure_success(reply: &Reply, method: &str, url: &str, what: &str) -> Result<()> {
    if (200..300).contains(&reply.code) {
        return Ok(());
    }
    // The first 512 bytes of the body: enough to carry a provider's error
    // message without printing a whole HTML page.
    let said = String::from_utf8_lossy(&reply.body[..reply.body.len().min(512)]);
    bail!(
        "{what}: {method} {url} answered {}: {}",
        reply.status,
        said.trim()
    );
}

#[cfg(test)]
mod tests {
    use super::split;

    #[test]
    fn splits_the_addresses_callers_name() {
        assert_eq!(
            split("https://api.pwnedpasswords.com/range/ABCDE").unwrap(),
            ("api.pwnedpasswords.com".into(), 443, "/range/ABCDE".into())
        );
        assert_eq!(
            split("https://gitlab.example:8443").unwrap(),
            ("gitlab.example".into(), 8443, "/".into())
        );
        assert_eq!(
            split("https://h.example?x=1").unwrap(),
            ("h.example".into(), 443, "/?x=1".into())
        );
        assert_eq!(
            split("https://[::1]:9/p").unwrap(),
            ("::1".into(), 9, "/p".into())
        );
        assert!(split("http://h.example/").is_err());
        assert!(split("https://user:pw@h.example/").is_err());
        assert!(split("https://h.example:port/").is_err());
    }
}
