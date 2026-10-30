//! Signature verification against the NIST CAVP FIPS 186-3 SigVer vectors:
//! ECDSA over P-256 and P-384 with SHA-256, SHA-384 and SHA-512, and RSA
//! PKCS#1 v1.5 and PSS with 1024-, 2048- and 3072-bit moduli and the same
//! hashes. Every case must give the stated result, P or F.

mod common;

use common::{hex, vector_file};
use skarbiec_crypto::ecdsa::{p256, p384, Curve};
use skarbiec_crypto::rsa::{HashAlg, PublicKey};

/// Records of a SigVer file in order, with the section each falls under.
fn records(file: &str) -> Vec<(String, Vec<(String, String)>)> {
    let text = vector_file(file);
    let mut out = Vec::new();
    let mut section = String::new();
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            if !fields.is_empty() {
                out.push((section.clone(), std::mem::take(&mut fields)));
            }
            section = line.to_string();
            continue;
        }
        if line.is_empty() {
            if !fields.is_empty() {
                out.push((section.clone(), std::mem::take(&mut fields)));
            }
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            fields.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    if !fields.is_empty() {
        out.push((section, fields));
    }
    out
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

fn hash_named(name: &str) -> Option<HashAlg> {
    match name {
        "SHA-256" | "SHA256" => Some(HashAlg::Sha256),
        "SHA-384" | "SHA384" => Some(HashAlg::Sha384),
        "SHA-512" | "SHA512" => Some(HashAlg::Sha512),
        _ => None,
    }
}

#[test]
fn ecdsa_p256_p384_sigver() {
    let curves: [(&str, Curve); 2] = [("P-256", p256()), ("P-384", p384())];
    let mut checked = 0;
    let (mut passed, mut failed) = (0, 0);
    for (section, fields) in records("ecdsa/SigVer.rsp") {
        let inner = section.trim_start_matches('[').trim_end_matches(']');
        let Some((curve_name, hash_name)) = inner.split_once(',') else {
            continue;
        };
        let Some((_, curve)) = curves.iter().find(|(name, _)| *name == curve_name) else {
            continue;
        };
        let Some(hash) = hash_named(hash_name) else {
            continue;
        };
        let get =
            |name: &str| field(&fields, name).unwrap_or_else(|| panic!("{section}: no {name}"));
        let digest = hash.digest(&hex(get("Msg")));
        let pad = |text: &str| {
            let bytes = hex(text);
            let mut out = vec![0u8; curve.size.saturating_sub(bytes.len())];
            out.extend(bytes);
            out
        };
        let valid = curve.verify(
            &pad(get("Qx")),
            &pad(get("Qy")),
            &digest,
            &hex(get("R")),
            &hex(get("S")),
        );
        let expected = get("Result").starts_with('P');
        assert_eq!(
            valid,
            expected,
            "{section} Qx = {} Result = {}",
            get("Qx"),
            get("Result")
        );
        if expected {
            passed += 1;
        } else {
            failed += 1;
        }
        checked += 1;
    }
    assert_eq!(
        checked,
        2 * 3 * 15,
        "P-256 and P-384 with three hashes, 15 cases each"
    );
    assert!(passed > 0 && failed > 0);
}

fn rsa_sigver(file: &str, pss: bool) -> usize {
    let mut checked = 0;
    let mut n = Vec::new();
    for (section, fields) in records(file) {
        if let Some(modulus) = field(&fields, "n") {
            n = hex(modulus);
            if field(&fields, "SHAAlg").is_none() {
                continue;
            }
        }
        let Some(hash) = field(&fields, "SHAAlg").and_then(hash_named) else {
            continue;
        };
        let get =
            |name: &str| field(&fields, name).unwrap_or_else(|| panic!("{section}: no {name}"));
        // CAVP writes e, Msg and S as integers, dropping a leading zero
        // digit (e = 9ffbd), so an odd-length value is padded with one zero,
        // and S, an octet string of the modulus's length (RFC 8017 8.2.2),
        // is padded back to that length.
        let integer = |text: &str| match text.len() % 2 {
            1 => hex(&format!("0{text}")),
            _ => hex(text),
        };
        let key = PublicKey::new(&n, &integer(get("e")));
        let message = integer(get("Msg"));
        let mut signature = integer(get("S"));
        if signature.len() < key.size() {
            let mut padded = vec![0; key.size() - signature.len()];
            padded.extend_from_slice(&signature);
            signature = padded;
        }
        let valid = if pss {
            let salt = hex(get("SaltVal"));
            let salt_len = if get("SaltVal") == "00" {
                0
            } else {
                salt.len()
            };
            key.verify_pss(hash, &message, &signature, salt_len)
        } else {
            key.verify_pkcs1v15(hash, &message, &signature)
        };
        let expected = get("Result").starts_with('P');
        assert_eq!(
            valid,
            expected,
            "{file} {section} Msg = {}… Result = {}",
            &get("Msg")[..16],
            get("Result")
        );
        checked += 1;
    }
    checked
}

#[test]
fn rsa_pkcs1v15_sigver() {
    let checked = rsa_sigver("rsa/SigVer15_186-3.rsp", false);
    assert!(checked >= 3 * 3 * 6, "{checked} cases");
}

#[test]
fn rsa_pss_sigver() {
    let checked = rsa_sigver("rsa/SigVerPSS_186-3.rsp", true);
    assert!(checked >= 3 * 3 * 6, "{checked} cases");
}
