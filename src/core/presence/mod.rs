//! Where a program is on a search path.
//!
//! `Path::is_file()` answers false for a candidate this process may not
//! examine, so a search built on it reads a program it cannot reach as one
//! that is not installed and moves on to a later directory, or reports none.
//! Here, as in `core::file_type`, only a candidate that is not there is
//! absent; any other failure is refused naming the candidate.

use anyhow::Result;
use std::ffi::OsStr;
use std::path::PathBuf;

/// The first file named `program` in the directories of `search` (a PATH
/// value), or `None` when no directory holds one. A directory element that
/// is not a directory holds nothing, as it holds nothing for `execvp`.
pub fn on_path(program: &str, search: &OsStr) -> Result<Option<PathBuf>> {
    for candidate in std::env::split_paths(search).map(|directory| directory.join(program)) {
        match std::fs::metadata(&candidate) {
            Ok(metadata) => {
                if metadata.is_file() {
                    return Ok(Some(candidate));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => {}
            Err(error) => {
                return Err(anyhow::Error::new(error).context(format!(
                    "examine {} while looking for {program} on PATH; make the directory readable to this account or remove it from PATH",
                    candidate.display()
                )))
            }
        }
    }
    Ok(None)
}
