// Value checks shared by every credential path, the operator-supplied flags
// and owner-only files a command reads before it acts, and the single-writer
// lock a credential operation holds while it owns the vault file.

mod checks;
mod inputs;
mod lock;

pub(super) const TOKEN_FILE_ENV: &str = "SKARBIEC_CREDENTIAL_TOKEN_FILE";

pub(super) use checks::{
    checked_bool, checked_code, checked_enum, checked_host, checked_timestamp, checked_uuid,
    hex_digest, present, safe_string, timestamp_shaped, uuid_shaped, zulu_seconds,
};
pub(super) use inputs::{
    client_identity, email_address, lowercase_uuid, opaque_handle, resume_handles,
};
pub(super) use lock::{
    acquire_credential_operation_lock, effective_uid, exact_name, now_iso, purpose,
};
