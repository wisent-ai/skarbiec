// `skarbiec rotate <id> --with <provider> [that provider's flags]`: the one
// operation that replaces an item's secret at the system that issued it and
// in the vault together, proving the new secret before the old one ends.
// Each provider is an adapter below — the database account, the AWS key, the
// Google Cloud key, the Microsoft Entra secret, the GitLab, Cloudflare,
// Twilio, SendGrid and Vercel tokens, the SSH key — whose usage line declares
// the flags it takes; a provider is added by adding an adapter, never a
// command. `rotation set <id> --every-days <N> --with <provider>` keeps the
// same call as a policy, and `rotation providers` lists the adapters.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::{OrUsage, Usage};

const USAGE: &str = "usage: rotate <id> --with <provider> [that provider's flags]; `skarbiec rotation providers` lists the providers and their flags";
pub(crate) const WITH: &str = "with";

pub(crate) struct Provider {
    pub(crate) name: &'static str,
    /// What it rotates, for `rotation providers`.
    about: &'static str,
    /// Its usage line, which names the flags it takes: a policy may keep
    /// only these.
    usage: &'static str,
    run: fn(&HashMap<String, String>, &str) -> Result<Value>,
}

impl Provider {
    /// The flags the provider takes besides --with, without their dashes.
    pub(crate) fn flags(&self) -> Vec<String> {
        crate::cli::help::flags_in(self.usage)
            .into_iter()
            .filter(|flag| flag != WITH)
            .collect()
    }
}

const PROVIDERS: &[Provider] = &[
    Provider { name: "database", about: "a PostgreSQL or MySQL account's password, in a login or host item", usage: crate::runtime::dbrotate::USAGE, run: crate::runtime::dbrotate::rotate_item },
    Provider { name: "aws", about: "an AWS IAM user's access key, in an access-key item", usage: crate::runtime::awsrotate::USAGE, run: crate::runtime::awsrotate::rotate_item },
    Provider { name: "gcp", about: "a Google Cloud service account key, in a service-account item", usage: crate::runtime::gcprotate::USAGE, run: crate::runtime::gcprotate::rotate_item },
    Provider { name: "azure", about: "a Microsoft Entra application's client secret, in an oauth-client item", usage: crate::runtime::azrotate::USAGE, run: crate::runtime::azrotate::rotate_item },
    Provider { name: "gitlab", about: "a GitLab access token, in a token item, through GitLab's self-rotation", usage: crate::runtime::gitlabrotate::USAGE, run: crate::runtime::gitlabrotate::rotate_item },
    Provider { name: "cloudflare", about: "a Cloudflare API token, in a token item, rolled by Cloudflare", usage: crate::runtime::cloudflarerotate::USAGE, run: crate::runtime::cloudflarerotate::rotate_item },
    Provider { name: "twilio", about: "a Twilio account's auth token, in an api-key item", usage: crate::runtime::twiliorotate::USAGE, run: crate::runtime::twiliorotate::rotate_item },
    Provider { name: "sendgrid", about: "a SendGrid API key, in a token item", usage: crate::runtime::sendgridrotate::USAGE, run: crate::runtime::sendgridrotate::rotate_item },
    Provider { name: "vercel", about: "a Vercel access token, in a token item", usage: crate::runtime::vercelrotate::USAGE, run: crate::runtime::vercelrotate::rotate_item },
    Provider { name: "ssh", about: "an SSH key pair, in a key-pair item, with the servers and forges holding its public key", usage: crate::runtime::keygen::SSH_ROTATE_USAGE, run: crate::runtime::keygen::rotate_ssh },
];

fn names() -> String {
    PROVIDERS
        .iter()
        .map(|provider| provider.name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Only a canonical provider name is an input to rotate, its API or a new policy.
/// Stored command spellings are migrated explicitly by `upgrade --apply`.
pub(crate) fn provider(name: &str) -> Result<&'static Provider> {
    match PROVIDERS.iter().find(|provider| provider.name == name) {
        Some(provider) => Ok(provider),
        None => Err(Usage(format!(
            "--with {name} is not a provider this vault rotates through; it rotates through {}",
            names()
        ))
        .into()),
    }
}

/// Run one rotation; a flag the provider does not take is refused before it
/// is asked, and the provider refuses missing or wrong flags in its own words.
pub(crate) fn run(provider: &Provider, flags: &HashMap<String, String>, id: &str) -> Result<Value> {
    let taken = provider.flags();
    if let Some(stray) = flags
        .keys()
        .find(|key| key.as_str() != WITH && !taken.contains(key))
    {
        return Err(Usage(format!(
            "--with {} takes no --{stray}; {}",
            provider.name, provider.usage
        ))
        .into());
    }
    let mut answer = (provider.run)(flags, id)?;
    answer["provider"] = json!(provider.name);
    Ok(answer)
}

/// Every provider with what it rotates and its usage.
pub(crate) fn providers() -> Value {
    let listed: Vec<Value> = PROVIDERS
        .iter()
        .map(|provider| json!({"provider": provider.name, "about": provider.about, "usage": provider.usage, "flags": provider.flags()}))
        .collect();
    json!({"providers": listed})
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "rotate" {
        return Ok(None);
    }
    let [id] = positionals else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let provider = provider(flags.get(WITH).or_usage(USAGE)?)?;
    run(provider, flags, id).map(Some)
}

#[derive(serde::Serialize)]
pub(crate) struct PolicyProviderChange {
    item: String,
    from: String,
    to: &'static str,
}

/// A metadata-only plan: preview neither rewrites the vault nor rotates a secret.
#[derive(serde::Serialize)]
pub(crate) struct PolicyUpgrade {
    applied: bool,
    changes: Vec<PolicyProviderChange>,
    unrecognized: Vec<Value>,
}

impl PolicyUpgrade {
    pub(crate) fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }

    pub(crate) fn apply(&mut self, document: &mut Value) -> Result<()> {
        for change in &self.changes {
            let saved = document
                .get_mut("rotation")
                .and_then(|policies| policies.get_mut(&change.item))
                .and_then(|policy| policy.get_mut("submission"))
                .and_then(|submission| submission.get_mut(WITH))
                .with_context(|| {
                    format!(
                        "rotation policy {} no longer holds its planned provider",
                        change.item
                    )
                })?;
            if saved.as_str() != Some(change.from.as_str()) {
                anyhow::bail!(
                    "rotation policy {} changed since its provider upgrade was planned",
                    change.item
                );
            }
            *saved = json!(change.to);
        }
        self.applied = true;
        Ok(())
    }
}

/// Decode old persisted metadata only, never an invocation's provider argument.
/// Unknown providers are retained and reported rather than guessed or discarded.
pub(crate) fn policy_upgrade(document: &Value) -> Result<PolicyUpgrade> {
    let mut plan = PolicyUpgrade {
        applied: false,
        changes: Vec::new(),
        unrecognized: Vec::new(),
    };
    let Some(section) = document.get("rotation") else {
        return Ok(plan);
    };
    let policies = section
        .as_object()
        .context("vault rotation section is not an object of policies")?;
    for (item, policy) in policies {
        let submission = policy
            .get("submission")
            .and_then(Value::as_object)
            .with_context(|| format!("rotation policy {item} holds no submission object"))?;
        let Some(saved) = submission.get(WITH) else {
            continue;
        };
        let saved = saved.as_str().with_context(|| {
            format!("rotation policy {item} submission.with is not a provider name")
        })?;
        if PROVIDERS.iter().any(|provider| provider.name == saved) {
            continue;
        }
        // The retired commands were <provider>-rotate, with db-rotate for
        // database. This conversion is confined to the explicit upgrade plan.
        let replacement = saved.strip_suffix("-rotate").and_then(|stem| {
            let name = match stem {
                "db" => "database",
                other => other,
            };
            PROVIDERS.iter().find(|provider| provider.name == name)
        });
        match replacement {
            Some(provider) => plan.changes.push(PolicyProviderChange {
                item: item.clone(),
                from: saved.to_string(),
                to: provider.name,
            }),
            None => plan.unrecognized.push(json!({
                "item": item,
                "provider": saved,
                "error": format!("rotation policy {item} names {saved:?}, which is neither a canonical provider nor a known stored command; set this policy with rotation set and a provider listed by rotation providers"),
            })),
        }
    }
    Ok(plan)
}
