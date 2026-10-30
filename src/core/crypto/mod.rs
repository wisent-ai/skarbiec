// Cryptographic operations for the skarbiec vault, all in this process on
// Skarbiec's own library (`crates/crypto`, no dependency of any kind):
// sealing items to each recipient's key, opening them, the keys themselves,
// signatures, hashes and entropy. No `gpg`, `gpg-agent`, `keyboxd` or
// `openssl` runs, so no request ever waits on another program. The
// per-recipient model (seal to each recipient's public key) is the same
// shape 1Password/Bitwarden use for sharing.

pub mod import;
mod keyring;
mod keys;
mod messages;
pub mod signature;

pub use keys::{
    export_public_key, export_public_keys, fingerprint_for, fingerprint_of_armored, generate_key,
    import_key, key_file, key_validity, secret_key_present,
};
pub use messages::{
    clearsign, decrypt, encrypt_to, encrypted_to, format_of, holder_of, random_token,
    seal_with_passphrase, sha1_hex_upper, sha256_hex, sha256_hex_bytes, verify_clearsigned, Format,
};
