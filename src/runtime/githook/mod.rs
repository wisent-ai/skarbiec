// `skarbiec hook install <repo> --fields <field,...> [--min-length <N>]
// [--replace] | hook status <repo> | hook uninstall <repo>`: a git
// pre-commit hook that runs `scan --refuse` over the files a commit adds or
// changes, so a password, token or key the vault keeps is stopped before it
// reaches a repository's history. The hook names this binary by its
// absolute path and is found where git looks for hooks (core.hooksPath
// included); an existing hook is replaced only with --replace, and
// uninstall removes only a hook this command wrote.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::args::{flag_set, OrUsage, Usage};

const USAGE: &str =
    "usage: hook install <repo> --fields <field,...> [--min-length <N>] [--replace] | hook status <repo> | hook uninstall <repo>";
/// The line every hook this command writes carries, so status and
/// uninstall tell it from a hook someone else wrote. It is what hooks
/// already written carry, so it is kept as written.
const MARKER: &str = "# Written by `skarbiec git-hook install`";
const HOOK: &str = "pre-commit";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "hook" {
        return Ok(None);
    }
    let [verb, repo] = positionals else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let repo = std::env::current_dir().context("read the working directory")?.join(repo);
    let path = hook_path(&repo)?;
    let answer = match verb.as_str() {
        "install" => install(&path, flags)?,
        "status" => status(&path)?,
        "uninstall" => uninstall(&path)?,
        other => return Err(Usage(format!("hook {other} is not install, status or uninstall; {USAGE}")).into()),
    };
    Ok(Some(answer))
}

/// Where git looks for this repository's pre-commit hook, as git itself
/// resolves it.
fn hook_path(repo: &Path) -> Result<PathBuf> {
    let asked = stado_wait::output(Command::new("git").arg("-C").arg(repo).args(["rev-parse", "--git-path", "hooks"]))
        .context("run git rev-parse, which names the repository's hooks directory")?;
    if !asked.status.success() {
        bail!(
            "{} is not a git repository git can read ({}): {}",
            repo.display(),
            asked.status,
            String::from_utf8_lossy(&asked.stderr).trim()
        );
    }
    let hooks = String::from_utf8(asked.stdout).context("git named the hooks directory in bytes that are not UTF-8")?;
    Ok(repo.join(hooks.trim()).join(HOOK))
}

fn ours(path: &Path) -> Result<bool> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(text.lines().any(|line| line.starts_with(MARKER)))
}

fn install(path: &Path, flags: &HashMap<String, String>) -> Result<Value> {
    let fields = flags.get("fields").or_usage(USAGE)?;
    let plain = |text: &str| text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ',');
    if fields.is_empty() || !plain(fields) {
        return Err(Usage(format!("--fields {fields} is not field names separated by commas; {USAGE}")).into());
    }
    let minimum = match flags.get("min-length") {
        Some(given) => {
            given.parse::<usize>().with_context(|| format!("--min-length {given} is not a whole number"))?;
            format!(" --min-length {given}")
        }
        None => String::new(),
    };
    if crate::core::is_present(path, "the pre-commit hook")? && !flag_set(flags, "replace") {
        bail!("{} already holds a pre-commit hook; add --replace to write this one over it", path.display());
    }
    let binary = std::env::current_exe().context("find this binary, which the hook runs")?;
    let shown = binary.display().to_string();
    if shown.contains('\'') {
        bail!("this binary's path {shown} holds a quote the hook could not name it with; install skarbiec where its path has none");
    }
    let script = format!(
        "#!/bin/sh\n{MARKER}: refuse a commit whose added or changed files hold a\n# value the vault keeps, in plain text. `skarbiec hook uninstall <repo>` removes it.\nstaged=$(git diff --cached --name-only --diff-filter=ACM)\n[ -z \"$staged\" ] && exit\nIFS='\n'\nexec '{shown}' scan $staged --fields '{fields}'{minimum} --refuse\n"
    );
    let directory = path.parent().context("the hook path has no directory")?;
    std::fs::create_dir_all(directory).with_context(|| format!("create {}", directory.display()))?;
    crate::core::vault::atomic_write(path, script.as_bytes()).with_context(|| format!("write {}", path.display()))?;
    // Executable as this binary is, so git runs it.
    let permissions = std::fs::metadata(&binary).with_context(|| format!("read {shown}'s permissions"))?.permissions();
    std::fs::set_permissions(path, permissions).with_context(|| format!("make {} executable", path.display()))?;
    crate::runtime::audit::append("git-hook-installed", &json!({"hook": path.display().to_string(), "fields": fields}))?;
    Ok(json!({"ok": true, "hook": path.display().to_string(), "installed": true, "fields": fields, "runs": shown}))
}

fn status(path: &Path) -> Result<Value> {
    let present = crate::core::is_present(path, "the pre-commit hook")?;
    let written_here = present && ours(path)?;
    Ok(json!({"ok": true, "hook": path.display().to_string(), "present": present, "installed": written_here}))
}

fn uninstall(path: &Path) -> Result<Value> {
    if !crate::core::is_present(path, "the pre-commit hook")? {
        bail!("{} holds no pre-commit hook; there is nothing to remove", path.display());
    }
    if !ours(path)? {
        bail!("{} was not written by skarbiec hook install; it is left as it is", path.display());
    }
    std::fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    crate::runtime::audit::append("git-hook-removed", &json!({"hook": path.display().to_string()}))?;
    Ok(json!({"ok": true, "hook": path.display().to_string(), "installed": false}))
}
