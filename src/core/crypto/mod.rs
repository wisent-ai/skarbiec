// Cryptographic operations for the skarbiec vault, delegated to vetted local
// tools — never hand-rolled:
//   gpg     : per-recipient public-key authenticated encryption + key material
//   openssl : entropy (random tokens)
//   shasum  : hashing (audit chain, breach k-anonymity)
// The per-recipient model (encrypt to each recipient's public key) is the same
// shape 1Password/Bitwarden use for sharing.

mod execution;
mod keys;
mod messages;

pub use execution::{executor_status, recover_daemons};
pub use keys::{
    export_public_key, fingerprint_for, generate_key, import_key, keygrips_for,
    secret_key_present,
};
pub use messages::{
    clearsign, decrypt, encrypt_to, random_token, sha1_hex_upper, sha256_hex,
    verify_clearsigned,
};
