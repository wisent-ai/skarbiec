// The two forges rotate --with ssh carries a key to, each through its own CLI's
// `api` command and the account that CLI is signed in as: GitHub through gh
// and GitLab through glab. A spot on a forge is a repository's deploy keys
// (GitHub's repos/<owner>/<name>/keys with read_only, GitLab's
// projects/<url-encoded path>/deploy_keys with can_push), the signed-in
// account's own SSH keys (user/keys; GitLab's carry a usage_type, which also
// covers commit signing), or GitHub's separate list of the account's signing
// keys (user/ssh_signing_keys). Everything else in a rotation is the same for
// every spot.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::process::Command;

#[derive(Clone, Copy)]
pub(in crate::runtime::keygen) enum Forge {
    GitHub,
    GitLab,
}

/// Where on a forge a key sits.
#[derive(Clone)]
pub(in crate::runtime::keygen) enum Spot {
    Repo(String),
    Account,
    Signing,
}

impl Forge {
    /// The rotate --with ssh flag naming this forge's repositories, and the name
    /// its rows carry in the answer.
    pub(in crate::runtime::keygen) fn flag(self) -> &'static str {
        match self {
            Forge::GitHub => "github",
            Forge::GitLab => "gitlab",
        }
    }

    /// The rotate --with ssh flag that carries the key to the signed-in account.
    pub(in crate::runtime::keygen) fn account_flag(self) -> &'static str {
        match self {
            Forge::GitHub => "github-account",
            Forge::GitLab => "gitlab-account",
        }
    }

    fn program(self) -> &'static str {
        match self {
            Forge::GitHub => "gh",
            Forge::GitLab => "glab",
        }
    }

    /// A repository as this forge names one: owner/name on GitHub, a group
    /// path with the project last on GitLab.
    pub(in crate::runtime::keygen) fn checked(self, repo: &str) -> Result<()> {
        let part = |text: &str| {
            !text.is_empty()
                && text
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        };
        let parts: Vec<&str> = repo.split('/').collect();
        let ok = match (self, parts.as_slice()) {
            (Forge::GitHub, [owner, name]) => part(owner) && part(name),
            (Forge::GitHub, _) => false,
            (Forge::GitLab, [_, _, ..]) => parts.iter().all(|segment| part(segment)),
            (Forge::GitLab, _) => false,
        };
        match (ok, self) {
            (true, _) => Ok(()),
            (false, Forge::GitHub) => {
                bail!("--github {repo} is not a GitHub repository as owner/name")
            }
            (false, Forge::GitLab) => {
                bail!("--gitlab {repo} is not a GitLab project as group/project")
            }
        }
    }

    /// Where a spot's keys are listed and added.
    pub(in crate::runtime::keygen) fn keys_path(self, spot: &Spot) -> String {
        match (self, spot) {
            (Forge::GitHub, Spot::Repo(repo)) => format!("repos/{repo}/keys"),
            (Forge::GitLab, Spot::Repo(repo)) => {
                format!("projects/{}/deploy_keys", repo.replace('/', "%2F"))
            }
            (_, Spot::Account) => "user/keys".to_string(),
            (_, Spot::Signing) => "user/ssh_signing_keys".to_string(),
        }
    }

    fn key_path(self, spot: &Spot, key_id: &Value) -> String {
        format!("{}/{key_id}", self.keys_path(spot))
    }

    /// The fields beyond title and key that make the new key do what the old
    /// one did: a deploy key's access, a GitLab account key's usage_type.
    pub(in crate::runtime::keygen) fn carried_fields(
        self,
        spot: &Spot,
        key: &Value,
    ) -> Result<Vec<String>> {
        match (self, spot) {
            (Forge::GitHub, Spot::Repo(_)) => {
                let read_only = key["read_only"]
                    .as_bool()
                    .context("the deploy key does not say whether it is read-only")?;
                Ok(vec![format!("read_only={read_only}")])
            }
            (Forge::GitLab, Spot::Repo(_)) => {
                let push = key["can_push"]
                    .as_bool()
                    .context("the deploy key does not say whether it may push")?;
                Ok(vec![format!("can_push={push}")])
            }
            (Forge::GitLab, Spot::Account) => Ok(key["usage_type"]
                .as_str()
                .map(|usage| format!("usage_type={usage}"))
                .into_iter()
                .collect()),
            (_, Spot::Account) | (_, Spot::Signing) => Ok(Vec::new()),
        }
    }

    /// Run `<program> api <args>` and answer its JSON, naming the CLI's words
    /// when it refuses.
    pub(in crate::runtime::keygen) fn api(self, args: &[String]) -> Result<Value> {
        let program = self.program();
        let output = stado_wait::output(Command::new(program).arg("api").args(args))
            .with_context(|| format!("run {program} api, which changes the forge's SSH keys"))?;
        if !output.status.success() {
            bail!(
                "{program} api {} ({}): {}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let text = String::from_utf8_lossy(&output.stdout);
        if text.trim().is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "{program} api {} answered something that is not JSON",
                    args.join(" ")
                )
            })
        }
    }

    pub(in crate::runtime::keygen) fn delete(self, spot: &Spot, key_id: &Value) -> Result<()> {
        self.api(&[
            "-X".to_string(),
            "DELETE".to_string(),
            self.key_path(spot, key_id),
        ])
        .map(|_| ())
    }

    /// The command that deletes a key by hand, for a refusal to name.
    pub(in crate::runtime::keygen) fn delete_command(self, spot: &Spot, key_id: &Value) -> String {
        format!(
            "{} api -X DELETE {}",
            self.program(),
            self.key_path(spot, key_id)
        )
    }
}
