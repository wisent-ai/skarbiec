// `rotate <id> --with ssh --github <owner/repo,...> --gitlab <group/project,...>
// --github-account --gitlab-account --github-signing`: carry a rotation to the
// spots on a forge that trust the key — repositories' deploy keys, the
// signed-in account's own SSH keys and GitHub's list of its signing keys —
// through gh or glab and the account each is signed in as (`forge`). For
// every spot the old public key is found among its keys — its id, title and
// whatever else it carries — and the new key is added beside it the same way,
// before the vault takes the new key; when one spot refuses, the new key is
// taken back off every spot it reached and nothing changes. Once the vault
// holds the new key, the old key is deleted from each spot; one that cannot
// be is named with the command that deletes it. Only public keys reach gh or
// glab.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

mod forge;
pub(in crate::runtime::keygen) use forge::{Forge, Spot};

/// One spot on one forge.
pub(in crate::runtime::keygen) struct Place {
    pub(in crate::runtime::keygen) forge: Forge,
    pub(in crate::runtime::keygen) spot: Spot,
}

impl Place {
    /// How a refusal, the journal and the answer name the place.
    pub(in crate::runtime::keygen) fn label(&self) -> String {
        match &self.spot {
            Spot::Repo(repo) => format!("{} {repo}", self.forge.flag()),
            Spot::Account => format!("the {} account's SSH keys", self.forge.flag()),
            Spot::Signing => format!("the {} account's signing keys", self.forge.flag()),
        }
    }

    fn kind(&self) -> &'static str {
        match self.spot {
            Spot::Repo(_) => "deploy",
            Spot::Account => "account",
            Spot::Signing => "signing",
        }
    }
}

/// One place the new key was added to, the new key's id, and the old key's
/// id to delete once the vault holds the new key.
pub(in crate::runtime::keygen) struct Added {
    place: Place,
    new_id: Value,
    old_id: Value,
}

/// The type and key of a public key line, without its comment.
fn bare(key: &str) -> Option<String> {
    let words: Vec<&str> = key.split_whitespace().collect();
    match words.as_slice() {
        [kind, body, ..] => Some(format!("{kind} {body}")),
        _ => None,
    }
}

/// Find the key matching `old` at one place and add `public` beside it the
/// same way.
fn add_one(place: &Place, old: &str, public: &str) -> Result<Added> {
    let forge = place.forge;
    let label = place.label();
    let keys = forge.api(&[forge.keys_path(&place.spot)])?;
    let found = keys
        .as_array()
        .into_iter()
        .flatten()
        .find(|key| key["key"].as_str().and_then(bare).as_deref() == Some(old))
        .with_context(|| format!("{label} hold no key matching the item's public key, so there is nothing there to rotate"))?;
    let title = found["title"]
        .as_str()
        .with_context(|| format!("{label}: the matching key has no title"))?;
    let mut args = vec![
        "-X".to_string(),
        "POST".to_string(),
        forge.keys_path(&place.spot),
        "-f".to_string(),
        format!("title={title}"),
        "-f".to_string(),
        format!("key={public}"),
    ];
    let carried = forge
        .carried_fields(&place.spot, found)
        .with_context(|| label.clone())?;
    args.extend(
        carried
            .into_iter()
            .flat_map(|field| ["-F".to_string(), field]),
    );
    let made = forge.api(&args)?;
    Ok(Added {
        place: Place {
            forge,
            spot: place.spot.clone(),
        },
        new_id: made["id"].clone(),
        old_id: found["id"].clone(),
    })
}

/// Add `public` at every place beside `old_public`; on a refusal take it
/// back off the ones it reached and fail.
pub(in crate::runtime::keygen) fn add_everywhere(
    places: &[Place],
    old_public: &str,
    public: &str,
) -> Result<Vec<Added>> {
    let old = bare(old_public).context("the item's public key is not an SSH public key line")?;
    let mut added: Vec<Added> = Vec::new();
    for place in places {
        match add_one(place, &old, public) {
            Ok(one) => added.push(one),
            Err(error) => match take_back(&added).as_slice() {
                [] => bail!("{}: {error:#}; the new key was taken back off every place it reached and the vault keeps the old pair", place.label()),
                left => bail!("{}: {error:#}; the vault keeps the old pair, but the new key could not be taken back off {}", place.label(), left.join("; ")),
            },
        }
    }
    Ok(added)
}

/// Take the new key back off every place it reached, when a later step of
/// the rotation failed; answers the places it could not be taken off, each
/// with why.
pub(in crate::runtime::keygen) fn take_back(added: &[Added]) -> Vec<String> {
    added
        .iter()
        .filter_map(|one| {
            one.place
                .forge
                .delete(&one.place.spot, &one.new_id)
                .err()
                .map(|undo| format!("{}: {undo:#}", one.place.label()))
        })
        .collect()
}

/// Delete the old key from every place the new one reached, answering each
/// place with whether its old key is gone.
pub(in crate::runtime::keygen) fn retire_everywhere(added: &[Added]) -> Vec<Value> {
    added
        .iter()
        .map(|one| {
            let (forge, spot) = (one.place.forge, &one.place.spot);
            let repo = match spot {
                Spot::Repo(repo) => Some(repo.as_str()),
                Spot::Account | Spot::Signing => None,
            };
            let row = json!({"forge": forge.flag(), "kind": one.place.kind(), "repo": repo, "place": one.place.label()});
            match forge.delete(spot, &one.old_id) {
                Ok(()) => {
                    let mut done = row;
                    done["retired_removed"] = json!(true);
                    done
                }
                Err(error) => {
                    let mut failed = row;
                    failed["retired_removed"] = json!(false);
                    failed["error"] = json!(format!("{error:#}"));
                    failed["remove_with"] = json!(forge.delete_command(spot, &one.old_id));
                    failed
                }
            }
        })
        .collect()
}
