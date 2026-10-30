//! A TLS 1.3 client (RFC 8446): the key schedule, the record layer, the
//! cipher suites it offers and the handshake. Certificates are checked by
//! `x509` before the handshake trusts the server's key.

pub mod record;
pub mod schedule;
pub mod suite;
