// The GitHub star request: after a person's fifth successful `set` or `get`
// on a terminal, Skarbiec asks once for a star on its public repository. The
// request is the `star-request` journey every Wisent product walks, run by the
// shared onboarding runtime and kept per user in
// `$XDG_STATE_HOME/skarbiec/onboarding.json` (default
// `~/.local/state/skarbiec/onboarding.json`); `skarbiec star` reads, dismisses
// and resets it. The threshold is the runtime's, the operator's number; the
// repository is this package's `repository`, the catalog's
// `star_repository`.

use std::collections::HashMap;

use anyhow::Result;
use wisent_onboarding_client::{JourneyError, ProductStarRequest, StarProduct};

use super::args::{emit, Usage};

const USAGE: &str = "star [status | dismiss | reset]";

fn request() -> Result<ProductStarRequest, JourneyError> {
    let product = StarProduct::from_package("skarbiec", "Skarbiec", env!("CARGO_PKG_REPOSITORY"))?;
    ProductStarRequest::new(product)
}

/// Count one `set` or `get` that succeeded, when a person reads this
/// terminal: the request, on the one that makes it, goes to standard error,
/// so standard output keeps only the value; a request that cannot be kept is
/// said there too, and the command's own answer stands.
pub(crate) fn observe() {
    match request() {
        Ok(request) => {
            request.observe_reporting();
        }
        Err(error) => {
            eprintln!("skarbiec: this run is not counted toward the GitHub star request: {error}")
        }
    }
}

/// `skarbiec star [status|dismiss|reset]`: the status as JSON, or as
/// `--text` lines, as every command answers.
pub(crate) fn command(_flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let verb = match positionals {
        [] => "status",
        [verb] if matches!(verb.as_str(), "status" | "dismiss" | "reset") => verb.as_str(),
        [verb] => {
            return Err(Usage(format!("star {verb} is not a form of star; usage: {USAGE}")).into())
        }
        [_, unexpected, ..] => {
            return Err(Usage(format!(
                "star: unexpected argument {unexpected:?}; usage: {USAGE}"
            ))
            .into())
        }
    };
    let answered = request()?
        .command(&[verb.to_string()], true)
        .map_err(anyhow::Error::msg)?;
    let document: serde_json::Value = serde_json::from_str(&answered)?;
    emit(&document)
}
