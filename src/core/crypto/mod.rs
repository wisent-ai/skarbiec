// Cryptographic operations for the skarbiec vault, delegated to vetted local
// tools — never hand-rolled:
//   gpg     : per-recipient public-key authenticated encryption + key material
// Everything else this module owns runs in process. Hashing (`sha2`, `sha1`),
// entropy (`/dev/urandom`) and timestamps used to be `shasum`, `openssl` and
// `date` children, and each one took a slot in the same bounded pool the gpg
// decryptions use: a grant metadata call that decrypts nothing took over ten
// seconds and `GET /readyz` nearly as long while verifier sweeps ran.
// The per-recipient model (encrypt to each recipient's public key) is the same
// shape 1Password/Bitwarden use for sharing.

pub mod ed25519;
mod execution;
mod keys;
mod messages;

pub use execution::in_flight::{agent_refusal, agent_waits};
pub use execution::{
    daemon_footprints, daemon_memory_limit_bytes, executor_status, human_size,
    keyring_lock_holders, recover_daemons, recycle_oversized_daemons, DAEMON_MEMORY_LIMIT_SETTING,
};
pub use keys::{
    encrypted_to, export_public_key, fingerprint_for, generate_key, import_key, keygrips_for,
    secret_key_present,
};
pub use messages::{
    clearsign, decrypt, encrypt_to, random_token, sha1_hex_upper, sha256_hex, verify_clearsigned,
};
