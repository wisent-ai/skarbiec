// Cryptographic operations for the skarbiec vault, delegated to vetted local
// tools — never hand-rolled:
//   gpg     : per-recipient public-key authenticated encryption + key material
// Everything else this module owns runs in process: hashing (`sha2`, `sha1`),
// entropy (`/dev/urandom`) and timestamps. A child process for each would take
// a slot in the bounded pool the gpg decryptions use, so a grant metadata call
// or `GET /readyz`, which decrypt nothing, would wait behind verifier sweeps.
// The per-recipient model (encrypt to each recipient's public key) is the same
// shape 1Password/Bitwarden use for sharing.

mod execution;
mod keys;
mod messages;
pub mod signature;

pub use execution::in_flight::{agent_refusal, agent_waits, note_agent_waits};
pub use execution::{
    daemon_footprints, daemon_memory_limit_bytes, deadline_seconds, executor_status, human_size,
    keyring_lock_holders, recover_daemons, recycle_oversized_daemons, serving,
    DAEMON_MEMORY_LIMIT_SETTING,
};
pub use keys::{
    encrypted_to, export_public_key, fingerprint_for, fingerprint_of_armored, generate_key,
    import_key, key_validity, keygrips_for, secret_key_present,
};
pub use messages::{
    clearsign, decrypt, encrypt_to, random_token, seal_with_passphrase, sha1_hex_upper, sha256_hex,
    verify_clearsigned,
};
