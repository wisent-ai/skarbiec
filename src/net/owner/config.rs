use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::process::{Command, Stdio};

pub(crate) fn selected() -> Result<Option<String>> {
    if std::env::var_os("SKARBIEC_VAULT_FILE").is_some() {
        return Ok(None);
    }
    let Some(path) = crate::core::stado_config_file() else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read vault routing declaration {}", path.display()))?;
    let config: Value = serde_json::from_str(&text)
        .with_context(|| format!("parse vault routing declaration {}", path.display()))?;
    if config
        .pointer("/secrets/skarbiec/vault_file")
        .and_then(Value::as_str)
        .is_some_and(|path| !path.trim().is_empty())
    {
        return Ok(None);
    }
    let Some(route) = config.pointer("/secrets/skarbiec/url") else {
        return Ok(None);
    };
    let route = route
        .as_str()
        .filter(|route| !route.trim().is_empty())
        .with_context(|| {
            format!(
                "{}: secrets.skarbiec.url must name the vault owner route",
                path.display()
            )
        })?;
    Ok(Some(route.trim().to_string()))
}

pub(super) fn resolve(route: &str) -> Result<String> {
    let Some(reference) = route.strip_prefix("stado://service/") else {
        return Ok(route.to_string());
    };
    let (service, query) = reference.split_once('?').context(
        "vault service route must name its consumer: stado://service/skarbiec?consumer=operator",
    )?;
    if service != "skarbiec" {
        bail!("vault owner route names service {service:?}, not skarbiec");
    }
    let mut consumer = None;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        if key != "consumer" || consumer.is_some() || value.is_empty() {
            bail!("vault owner route has an invalid or repeated parameter {key:?}");
        }
        consumer = Some(value.into_owned());
    }
    let consumer = consumer.context("vault owner service route has no consumer")?;
    let output = stado_wait::output(
        Command::new("stado")
            .args([
                "service",
                "directory",
                "connect",
                service,
                "--consumer",
                &consumer,
                "--no-verify",
                "--json",
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::inherit()),
    )
    .with_context(|| format!("resolve vault owner {route} through Stado service directory"))?;
    if !output.status.success() {
        bail!("Stado service directory refused vault owner {route}: {}; its operation cause is on stderr", output.status);
    }
    let answer: Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("Stado service directory returned invalid JSON for {route}"))?;
    answer
        .get("url")
        .and_then(Value::as_str)
        .filter(|url| !url.is_empty())
        .map(str::to_string)
        .with_context(|| format!("Stado service directory returned no resolved url for {route}"))
}
