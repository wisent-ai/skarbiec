// `skarbiec ssh sign <ca-id> <public-key-file> --identity <name> --principals
// <a,b> --validity <window>`: sign one SSH public key with a certificate
// authority key the vault keeps, so servers that trust the authority accept
// the key for the principals and the window named, and no server's
// authorized_keys lists every person. The authority's private key goes from
// the item into the owner-only workspace ssh new uses, ssh-keygen -s
// signs there, and the workspace is removed before the answer, so the key
// never stays on disk. The certificate is public and is printed.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use crate::cli::args::Usage;
use crate::core::{schema, vault::Vault, vault_path};

const USAGE: &str = "usage: ssh sign <ca-id> <public-key-file> --identity <name> --principals <name,...> --validity <ssh-keygen -V window, such as +1h> [--host]";

pub(super) fn sign(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let [ca, public_file] = positionals else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let required = |name: &str| {
        flags
            .get(name)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| Usage(format!("--{name} is required; {USAGE}")))
    };
    let (identity, principals, validity) = (required("identity")?, required("principals")?, required("validity")?);
    let public_key = std::fs::read_to_string(public_file)
        .with_context(|| format!("read the public key to sign, {public_file}"))?;
    let path = vault_path();
    let payload = Vault::open(path.clone())?.get_item(ca)?;
    let ca_key = schema::fields(&payload)?
        .get("private_key")
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .with_context(|| format!("{ca} holds no private_key text, so there is no authority to sign with"))?
        .to_string();
    let work = super::workspace(&path)?;
    let ca_file = work.0.join("ca");
    let user_file = work.0.join("user.pub");
    let mut ca_text = ca_key;
    if !ca_text.ends_with('\n') {
        ca_text.push('\n');
    }
    // ssh-keygen loads only a private key nobody else can read.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(crate::core::vault::private_file_mode()?)
        .open(&ca_file)
        .and_then(|mut file| file.write_all(ca_text.as_bytes()))
        .context("hand the authority key to ssh-keygen")?;
    std::fs::write(&user_file, public_key).context("hand the public key to ssh-keygen")?;
    // `--host` signs a server's host key, which clients that trust the
    // authority then accept without a known_hosts entry.
    let mut command = Command::new("ssh-keygen");
    command.args(["-q", "-s"]).arg(&ca_file).args(["-I", identity, "-n", principals, "-V", validity]);
    let host = crate::cli::args::flag_set(flags, "host");
    if host {
        command.arg("-h");
    }
    let signed = stado_wait::output(command.arg(&user_file)).context("run ssh-keygen -s")?;
    if !signed.status.success() {
        bail!(
            "ssh-keygen refused to sign {public_file} with {ca} ({}): {}",
            signed.status,
            String::from_utf8_lossy(&signed.stderr).trim()
        );
    }
    let cert_file = work.0.join("user-cert.pub");
    let certificate = std::fs::read_to_string(&cert_file)
        .with_context(|| format!("read the certificate ssh-keygen wrote to {}", cert_file.display()))?
        .trim()
        .to_string();
    drop(work);
    crate::runtime::audit::append(
        "ssh-cert-signed",
        &json!({"ca": ca, "identity": identity, "principals": principals, "validity": validity, "host": host}),
    )?;
    Ok(json!({
        "ok": true,
        "ca": ca,
        "identity": identity,
        "principals": principals,
        "validity": validity,
        "host": host,
        "certificate": certificate,
    }))
}
