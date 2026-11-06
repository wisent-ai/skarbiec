//! Random bytes from the operating system's `/dev/urandom`, read whole.

use std::io::Read;

/// `n` random bytes; a failed open or a short read is the error, never
/// fewer random bytes.
pub fn bytes(n: usize) -> std::io::Result<Vec<u8>> {
    let mut out = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut out))
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("read {n} random bytes from /dev/urandom: {error}"),
            )
        })?;
    Ok(out)
}

/// 32 random bytes.
pub fn key() -> std::io::Result<[u8; 32]> {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes(32)?);
    Ok(out)
}
