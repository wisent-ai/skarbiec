//! The executable the one process was started from, and whether an install
//! has since replaced it.
//!
//! An installer replaces `~/.stado/bin/skarbiec` by renaming a new file over
//! it (wisent-products' `copy_installed`, Stado's `release install-local`),
//! and the running process goes on executing the old image: `stado service
//! ensure` then reads the same program path and the same unit and answers
//! `already_correct`. On lukasz-macbook on 2026-09-23 the hourly CLI sweep
//! installed skarbiec 0.4.2 while 0.3.16 kept serving, until a changed
//! declaration made `service ensure` reload the unit. Started as its declared
//! unit, the one process compares its image with the installed file before
//! each connection it accepts and ends once they differ, so launchd starts
//! the release that was installed.

use anyhow::{anyhow, Result};
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
    /// start again.
    pub(super) fn when_declared() -> Option<Self> {
        if !super::predecessors::declared() {
            return None;
        }
        let path = std::env::current_exe().ok()?;
        let started = std::fs::metadata(&path).ok()?;
        Some(Self {
            path,
            device: started.dev(),
            inode: started.ino(),
        })
    }

    /// `Err` once the path this process was started from names another file.
    /// A path missing for the instant of a rename is not a replacement yet.
    pub(super) fn unchanged(&self) -> Result<()> {
        let Ok(installed) = std::fs::metadata(&self.path) else {
            return Ok(());
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
