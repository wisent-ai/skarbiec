//! The executable the one process was started from, and whether an install
//! has since replaced it.
//!
//! An installer replaces `~/.stado/bin/skarbiec` by renaming a new file over
//! it (`stado product install`, Stado's `release install-local`),
//! and the running process goes on executing the old image: `stado service
//! ensure` then reads the same program path and the same unit and answers
//! `already_correct`. A scheduled CLI sweep can install a new release while
//! the old one keeps serving, until a changed declaration happens to make
//! `service ensure` reload the unit. Started as its declared
//! unit, the one process compares its image with the installed file before
//! each connection it accepts and ends once they differ, so launchd starts
//! the release that was installed.

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

#[derive(Clone)]
pub(super) struct Image {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Image {
    /// The running image when launchd started this process as its declared
    /// unit; `None` for a serve run by hand or by a test, which nothing would
    /// start again. A declared unit whose image cannot be read is refused:
    /// serving without the watch would keep an old release running after an
    /// install, the case this exists to end.
    pub(super) fn when_declared() -> Result<Option<Self>> {
        if !super::predecessors::declared() {
            return Ok(None);
        }
        let path = std::env::current_exe()
            .context("read the executable this declared Skarbiec unit runs")?;
        let started = std::fs::metadata(&path)
            .with_context(|| format!("read the running image {}", path.display()))?;
        Ok(Some(Self {
            path,
            device: started.dev(),
            inode: started.ino(),
        }))
    }

    /// `Err` once the path this process was started from names another file.
    /// A path missing for the instant of a rename is not a replacement yet; a
    /// path that cannot be read for another reason is said and ends serving.
    pub(super) fn unchanged(&self) -> Result<()> {
        let installed = match std::fs::metadata(&self.path) {
            Ok(installed) => installed,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(anyhow!(
                    "cannot read the installed image {} to compare with the running one: {error}",
                    self.path.display()
                ))
            }
        };
        if installed.dev() == self.device && installed.ino() == self.inode {
            return Ok(());
        }
        let image = self.path.display().to_string();
        if let Err(error) =
            crate::runtime::audit::append("serve-replaced", &json!({"image": image}))
        {
            eprintln!("skarbiec serve: could not journal the replaced image: {error:#}");
        }
        Err(anyhow!(
            "{image} was replaced by an install; ending so launchd starts the installed release"
        ))
    }
}
