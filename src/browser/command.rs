// `skarbiec browser <verb>`: connect the autofill extension on this machine
// (install), take it away (uninstall), say whether it is connected (status),
// widen its grant to every live login (cover), and `host`, the
// native-messaging host the browser itself starts.
//
// The manifests `install` writes name this binary itself, and a browser
// starts a host with arguments of its own: Chrome with the extension's
// origin, Firefox with the manifest's path and the extension's id. Those
// arguments are what `launched` reads, so the host answers however it is
// started.

use anyhow::Result;
use std::collections::HashMap;

const USAGE: &str = "usage: browser install [--binary <path>] | browser uninstall | browser status | browser cover | browser host  (started by the browser through the native-messaging manifest)";

pub fn command(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let answer = match positionals {
        [verb] if verb == "install" => super::install_host(flags)?,
        [verb] if verb == "uninstall" => super::uninstall_host()?,
        [verb] if verb == "status" => super::host_status()?,
        [verb] if verb == "cover" => super::cover_all()?,
        [verb] if verb == "host" => return crate::native_host::run(),
        _ => return Err(crate::cli::args::Usage(USAGE.to_string()).into()),
    };
    crate::cli::args::emit(&answer)
}

/// Whether this process was started by a browser through the manifest
/// `install` wrote: Chrome's first argument is the extension's origin, and
/// Firefox's is the path of the manifest it read.
pub fn launched(first: &str) -> Result<bool> {
    if first == super::chrome_origin() {
        return Ok(true);
    }
    // Only a word naming the host's manifest file can be Firefox's; every
    // other command is answered without reading where HOME keeps it.
    if !first.ends_with(&super::manifest_name()) {
        return Ok(false);
    }
    let paths = super::HostPaths::of(&super::home_dir()?);
    Ok(std::path::Path::new(first) == paths.firefox)
}
