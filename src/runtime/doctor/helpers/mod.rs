// Whether the programs git, Docker, AWS, kubectl, Terraform and Cargo were
// told to ask for credentials are still there. `skarbiec helper setup <tool>`
// names this binary by its absolute path; when an upgrade moves the binary,
// the tool runs a program that no longer exists, and a push or a cloud call
// fails with "command not found" far from the cause. This check reads each
// tool's own configuration and names each setting whose program is gone,
// with the command that points it at the binary again, and the sign-ins
// still left in plain text beside a helper that answers for them.

use serde_json::Value;

use super::{check, FAIL, NOT_CONFIGURED, PASS};

const NAME: &str = "helpers";

mod bindings;
mod ci;
mod plain;
mod rotations;
pub(in crate::runtime::doctor) use bindings::bindings_files_check;
pub(in crate::runtime::doctor) use ci::ci_secrets_check;
pub(in crate::runtime::doctor) use plain::developer_tokens_check;
pub(in crate::runtime::doctor) use rotations::rotations_check;

pub(in crate::runtime::doctor) fn helpers_check() -> Value {
    let forges = match crate::runtime::gitcred::configured() {
        Ok(forges) => forges,
        Err(error) => return check(NAME, FAIL, format!("{error:#}")),
    };
    let (docker_config, registries) = match crate::runtime::dockercred::registries() {
        Ok(found) => found,
        Err(error) => return check(NAME, FAIL, format!("{error:#}")),
    };
    let (aws_config, profiles) = match crate::runtime::awscred::profiles() {
        Ok(found) => found,
        Err(error) => return check(NAME, FAIL, format!("{error:#}")),
    };
    // Without kubectl no kubeconfig user can run the plugin.
    let kube_users = match crate::runtime::kubecred::kubectl_on_path() {
        true => match crate::runtime::kubecred::users() {
            Ok(found) => found,
            Err(error) => return check(NAME, FAIL, format!("{error:#}")),
        },
        false => Vec::new(),
    };
    let terraform = match crate::runtime::tfcred::status() {
        Ok(state) => state,
        Err(error) => return check(NAME, FAIL, format!("{error:#}")),
    };
    let terraform_asks = terraform["configured"] == serde_json::json!(true);
    let cargo = match crate::runtime::cargocred::status() {
        Ok(state) => state,
        Err(error) => return check(NAME, FAIL, format!("{error:#}")),
    };
    let cargo_asks = cargo["configured"] == serde_json::json!(true);
    // npm reads a token from the vault through a ${NAME} line exec fills.
    let (npmrc, npm_signins) = match crate::runtime::npmcred::signins() {
        Ok(found) => found,
        Err(error) => return check(NAME, FAIL, format!("{error:#}")),
    };
    let npm_asks = npm_signins.iter().any(|signin| signin.reference().is_some());
    if forges.is_empty() && registries.is_empty() && profiles.is_empty() && kube_users.is_empty() && !terraform_asks && !cargo_asks && !npm_asks {
        return check(NAME, NOT_CONFIGURED, "neither git, Docker, AWS, kubectl, Terraform, Cargo nor npm asks this vault for credentials".into());
    }
    let mut problems = Vec::new();
    if terraform_asks && terraform["program_present"] != serde_json::json!(true) {
        problems.push(format!(
            "Terraform's {} runs {}, which no longer leads to this binary; remove it, then skarbiec helper setup terraform links it again",
            terraform["config"], terraform["program"]
        ));
    }
    let plain: Vec<&str> = terraform["hosts_in_file"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    if terraform_asks && !plain.is_empty() {
        problems.push(format!(
            "{} still holds Terraform tokens for {} in plain text, which Terraform no longer reads; skarbiec helper import terraform <id> --host <host> moves each into the vault",
            terraform["tokens_file"],
            plain.join(", ")
        ));
    }
    // Cargo's provider names this binary by its absolute path too.
    let cargo_plain: Vec<&str> = cargo["registries_in_file"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    if cargo_asks && !cargo_plain.is_empty() {
        problems.push(format!(
            "{} still holds Cargo tokens for {} in plain text beside this vault's provider; skarbiec helper import cargo <id> --registry <name> --host <index host> moves each into the vault",
            cargo["credentials"],
            cargo_plain.join(", ")
        ));
    }
    if let Some(program) = cargo["program"].as_str().filter(|_| cargo_asks) {
        if !std::path::Path::new(program).exists() {
            problems.push(format!(
                "Cargo's {} runs {program}, which no longer exists; skarbiec helper unset cargo, then helper setup cargo, points it at this binary",
                cargo["config"]
            ));
        }
    }
    for profile in &profiles {
        if !profile.program.exists() {
            problems.push(format!(
                "AWS profile {} in {} runs {}, which no longer exists; skarbiec helper setup aws {} --profile {} points it at this binary",
                profile.name,
                aws_config.display(),
                profile.program.display(),
                profile.item,
                profile.name
            ));
        }
    }
    for user in &kube_users {
        if !user.program.exists() {
            problems.push(format!(
                "kubeconfig user {} runs {}, which no longer exists; skarbiec helper setup kube {} --user {} points it at this binary",
                user.name,
                user.program.display(),
                user.item,
                user.name
            ));
        }
    }
    for (host, program) in &forges {
        if !program.exists() {
            problems.push(format!(
                "git asks {} for {host}, which no longer exists; skarbiec helper setup git {host} points it at this binary",
                program.display()
            ));
        }
    }
    // git asks its helpers in turn; a store line for the same host still
    // holds the token in plain text, whichever answers first.
    match crate::runtime::gitcred::stored_hosts() {
        Err(error) => problems.push(format!("{error:#}")),
        Ok(stored) => {
            for (file, host) in stored.iter().filter(|(_, host)| forges.iter().any(|(asked, _)| asked == host)) {
                problems.push(format!(
                    "{} still keeps a plain-text sign-in for {host}, which git asks this vault for; skarbiec helper import git <id> {host} moves it into the vault",
                    file.display()
                ));
            }
        }
    }
    if !registries.is_empty() {
        match crate::runtime::dockercred::program_on_path() {
            Err(error) => problems.push(format!("{error:#}")),
            Ok(None) => problems.push(format!(
                "Docker's {} sends {} here, but no {} is on PATH; skarbiec helper setup docker <registry> --link <dir on PATH> links it",
                docker_config.display(),
                registries.join(", "),
                crate::runtime::dockercred::PROGRAM
            )),
            // A link whose binary has moved exists as a link but leads nowhere.
            Ok(Some(program)) if !program.exists() => problems.push(format!(
                "{} leads to a binary that no longer exists; remove it, then skarbiec helper setup docker <registry> --link <its directory> links it again",
                program.display()
            )),
            Ok(Some(_)) => {}
        }
        match crate::runtime::dockercred::plain_auths() {
            Err(error) => problems.push(format!("{error:#}")),
            Ok(plain) => {
                for registry in plain.iter().filter(|registry| registries.contains(registry)) {
                    problems.push(format!(
                        "Docker's {} still keeps a base64 sign-in for {registry} under auths, which Docker asks this vault for; remove it there, or skarbiec helper import docker <id> {registry} --link <dir> moves it into a new item",
                        docker_config.display()
                    ));
                }
            }
        }
    }
    let npm_plain: Vec<&str> = npm_signins.iter().filter(|signin| signin.reference().is_none()).map(|signin| signin.registry.as_str()).collect();
    if npm_asks && !npm_plain.is_empty() {
        problems.push(format!(
            "{} still holds npm tokens for {} in plain text beside the ones read from the vault; skarbiec tool import npm <id> --select <registry> --bindings <file> moves each into the vault",
            npmrc.display(),
            npm_plain.join(", ")
        ));
    }
    if problems.is_empty() {
        return check(
            NAME,
            PASS,
            format!(
                "git asks this vault for {} forges, Docker for {} registries, AWS for {} profiles and kubectl for {} users{}{}{}, every program in place",
                forges.len(),
                registries.len(),
                profiles.len(),
                kube_users.len(),
                match terraform_asks {
                    true => ", Terraform for its tokens",
                    false => "",
                },
                match cargo_asks {
                    true => ", Cargo for registry tokens",
                    false => "",
                },
                match npm_asks {
                    true => ", npm through exec",
                    false => "",
                }
            ),
        );
    }
    check(NAME, FAIL, problems.join("; "))
}
