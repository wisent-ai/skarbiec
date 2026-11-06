use anyhow::{bail, Context, Result};
use serde_json::Value;

pub(crate) fn selected() -> Result<Option<String>> {
    if std::env::var_os("SKARBIEC_VAULT_FILE").is_some() {
        return Ok(None);
    }
    let Some(path) = crate::core::stado_config_file().map_err(anyhow::Error::msg)? else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read vault routing declaration {}", path.display()))?;
    let config: Value = serde_json::from_str(&text)
        .with_context(|| format!("parse vault routing declaration {}", path.display()))?;
    let config = config.as_object().with_context(|| {
        format!(
            "{}: vault routing declaration must be an object",
            path.display()
        )
    })?;
    let Some(secrets) = config.get("secrets") else {
        return Ok(None);
    };
    let secrets = secrets
        .as_object()
        .with_context(|| format!("{}: secrets must be an object", path.display()))?;
    let Some(skarbiec) = secrets.get("skarbiec") else {
        return Ok(None);
    };
    let skarbiec = skarbiec
        .as_object()
        .with_context(|| format!("{}: secrets.skarbiec must be an object", path.display()))?;
    if let Some(vault) = skarbiec.get("vault_file") {
        vault
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .with_context(|| {
                format!(
                    "{}: secrets.skarbiec.vault_file must name a non-empty vault path",
                    path.display()
                )
            })?;
        return Ok(None);
    }
    let Some(route) = skarbiec.get("url") else {
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
    // This host's Stado resolver answers the adapter it reaches the owner
    // through, asked in process: no Stado program is started.
    crate::net::stado_route::route(service, &consumer)
        .with_context(|| format!("resolve vault owner {route} through this host's Stado resolver"))
}
