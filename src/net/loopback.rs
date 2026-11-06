//! One HTTP/1.1 exchange with a program on this host's loopback interface,
//! in process: the Stado resolver, and the adapters it listens on for the
//! services Skarbiec calls. Only `http://` to a loopback address is spoken;
//! a reply is read whole, as `Content-Length`, chunked transfer coding, or
//! up to the close states its end. A run a Stado schedule started ends the
//! exchange by that schedule's next firing (`net::deadline`).

use anyhow::{bail, Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;

/// A reply: its status code, its status line as sent, and its body.
pub(crate) struct Reply {
    pub code: u16,
    pub status: String,
    pub body: Vec<u8>,
}

/// The `host:port` of a loopback `http://` URL, refusing any other: an
/// address off this host needs a TLS client this exchange is not.
pub(crate) fn loopback_authority(url: &str) -> Result<SocketAddr> {
    let Some(rest) = url.strip_prefix("http://") else {
        bail!(
            "{url} is not an http:// address on this host's loopback interface, the only kind \
             Skarbiec dials in process; the route Stado answers for a service on another host \
             is this host's resolver adapter, so ask the resolver for it again"
        );
    };
    let authority = match rest.split_once('/') {
        Some((authority, _)) => authority,
        None => rest,
    };
    let address: SocketAddr = authority
        .replace("localhost", "127.0.0.1")
        .parse()
        .with_context(|| format!("{url} does not name a numeric loopback address and port"))?;
    if !address.ip().is_loopback() {
        bail!("{url} is not on this host's loopback interface; Skarbiec dials only loopback addresses in process");
    }
    Ok(address)
}

/// The head of one HTTP/1.1 request to `host`: `headers` as given after
/// Host, and the body's length when there is one; refused when a header
/// would break the request.
pub(crate) fn request_head(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    what: &str,
) -> Result<String> {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in headers {
        if value.contains(['\r', '\n']) || name.contains(['\r', '\n', ':']) {
            bail!("{what}: header {name} holds a line break, which would end the request early");
        }
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    Ok(request)
}

/// Send one request to `address` and read its reply. `headers` are sent as
/// given after Host; the body, when there is one, is sent with its length.
pub(crate) fn exchange(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    what: &str,
) -> Result<Reply> {
    let request = request_head(method, path, &address.to_string(), headers, body, what)?;
    let held = super::deadline::Deadline::of_this_run()?;
    stado_wait::blocking(stado_wait::Kind::Network, what, address, || {
        let mut stream = super::deadline::connect(address, held.as_ref())?;
        stream.write_all(request.as_bytes())?;
        if let Some(body) = body {
            stream.write_all(body)?;
        }
        stream.flush()?;
        read_reply(BufReader::new(stream))
    })
    .with_context(|| format!("{what}: {method} {path} at {address}"))
}

/// The reply on `reader`, read to the end its headers state. A body is read
/// as it arrives, never allocated from the server's `Content-Length` or chunk
/// size, so a length the server does not send costs nothing.
pub(crate) fn read_reply(mut reader: impl BufRead) -> std::io::Result<Reply> {
    let invalid = |detail: String| std::io::Error::new(std::io::ErrorKind::InvalidData, detail);
    let mut status = String::new();
    if reader.read_line(&mut status)? == 0 {
        return Err(invalid(
            "the connection closed before a status line was sent".to_string(),
        ));
    }
    let status = status.trim_end().to_string();
    let code = status
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .filter(|_| status.starts_with("HTTP/1."))
        .ok_or_else(|| invalid(format!("the status line {status:?} is not HTTP/1.x")))?;
    let mut length: Option<u64> = None;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(invalid(
                "the connection closed inside the reply's headers".to_string(),
            ));
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(invalid(format!("the header line {line:?} has no colon")));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length =
                Some(value.parse().map_err(|_| {
                    invalid(format!("Content-Length {value:?} is not a whole number"))
                })?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .rsplit(',')
                .next()
                .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked"));
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut size = String::new();
            if reader.read_line(&mut size)? == 0 {
                return Err(invalid(
                    "the connection closed inside a chunked body".to_string(),
                ));
            }
            let line = size.trim_end();
            let digits = match line.split_once(';') {
                Some((digits, _extensions)) => digits.trim(),
                None => line.trim(),
            };
            let size = u64::from_str_radix(digits, 16)
                .map_err(|_| invalid(format!("the chunk size {digits:?} is not hexadecimal")))?;
            if size == 0 {
                // Trailers, up to the blank line that ends them.
                loop {
                    let mut trailer = String::new();
                    if reader.read_line(&mut trailer)? == 0 || trailer.trim_end().is_empty() {
                        break;
                    }
                }
                break;
            }
            read_stated(&mut reader, size, &mut body, "a chunk")?;
            let mut end = [0u8; 2];
            reader.read_exact(&mut end)?;
            if &end != b"\r\n" {
                return Err(invalid("a chunk does not end with CRLF".to_string()));
            }
        }
    } else if let Some(length) = length {
        read_stated(&mut reader, length, &mut body, "the body")?;
    } else {
        reader.read_to_end(&mut body)?;
    }
    Ok(Reply { code, status, body })
}

/// Append the `stated` bytes `what` holds to `body`, as they arrive; refused
/// when the connection closes before they all came.
fn read_stated(
    reader: &mut impl BufRead,
    stated: u64,
    body: &mut Vec<u8>,
    what: &str,
) -> std::io::Result<()> {
    let got = reader.by_ref().take(stated).read_to_end(body)?;
    if (got as u64) < stated {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!(
                "the reply states {stated} bytes for {what} and the connection closed after {got}"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::read_reply;

    #[test]
    fn reads_each_way_a_reply_states_its_end() {
        let sized =
            read_reply(&b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}extra"[..]).unwrap();
        assert_eq!((sized.code, sized.body.as_slice()), (200, &b"{}"[..]));
        let chunked = read_reply(
            &b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"a\r\n4;x=y\r\n\":1}\r\n0\r\n\r\n"[..],
        )
        .unwrap();
        assert_eq!(
            (chunked.code, chunked.body.as_slice()),
            (201, &b"{\"a\":1}"[..])
        );
        let closed = read_reply(&b"HTTP/1.0 503 Service Unavailable\r\n\r\n{\"e\":1}"[..]).unwrap();
        assert_eq!(
            (closed.code, closed.body.as_slice()),
            (503, &b"{\"e\":1}"[..])
        );
        assert!(read_reply(&b"SSH-2.0-OpenSSH\r\n\r\n"[..]).is_err());
        // A length the server never sends is refused once the connection
        // closes, without allocating it first.
        let Err(huge) =
            read_reply(&b"HTTP/1.1 200 OK\r\nContent-Length: 1099511627776\r\n\r\n{}"[..])
        else {
            panic!("a body the server stops short of was read whole");
        };
        assert!(
            huge.to_string()
                .contains("1099511627776 bytes for the body"),
            "{huge}"
        );
        let Err(chunk) = read_reply(
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffff\r\n{}"[..],
        ) else {
            panic!("a chunk the server stops short of was read whole");
        };
        assert!(chunk.to_string().contains("for a chunk"), "{chunk}");
        assert!(
            read_reply(&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"[..])
                .is_err()
        );
    }
}
