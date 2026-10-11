//! Removing a file Skarbiec wrote beside its target and no longer needs: a
//! staging file whose write or rename failed, a lock the operation that held
//! it is releasing, or a ciphertext handed to gpg.
//!
//! A removal that fails leaves the file on disk. A staging file named per
//! process and opened with `create_new` then refuses the server's next write
//! as existing, and a lock that stays refuses every later writer as "another
//! process owns" it while no process does. So the failure is said, never
//! dropped; a file that is already gone is not a failure.

use std::path::Path;

/// Remove `path`. `Some` is the sentence that says the file is still there
/// and why; `None` when it is gone, including when it never existed.
pub fn remove(path: &Path) -> Option<String> {
    match std::fs::remove_file(path) {
        Ok(()) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => Some(format!("{} is left behind: {error}", path.display())),
    }
}

/// Remove `path` and print, on stderr, the sentence of one that stays, led by
/// `what` so the reader knows which file it was.
pub fn remove_said(path: &Path, what: &str) {
    if let Some(left) = remove(path) {
        eprintln!("skarbiec: {what}: {left}");
    }
}
