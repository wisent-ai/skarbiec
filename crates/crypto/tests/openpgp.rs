//! The OpenPGP reader against what GnuPG 2.5 wrote in a fixture home
//! (tests/vectors/openpgp, made once with real gpg; gpg is not run here):
//! its keyboxd database and key files, armored public keys, messages in the
//! OCB encrypted data packet and in CFB with an MDC (one and two
//! recipients, small and 400 KB), passphrase-sealed messages, and a
//! cleartext signature. The OCB packet is also checked against LibrePGP
//! A.3.4's sample. Every damaged input is refused with its cause.
#![allow(
    clippy::disallowed_methods,
    reason = "the test writes its own evidence files under target; the owner-only rule binds the product's writers"
)]

mod common;

use common::{hex, to_hex};
use skarbiec_crypto::openpgp::agent::{is_protected, read_key_file};
use skarbiec_crypto::openpgp::armor::{armor, crc24, dearmor};
use skarbiec_crypto::openpgp::keyboxd::read_pubring_db;
use skarbiec_crypto::openpgp::keys::{
    parse_public_keys, transferable_public_key, verify_self_signatures, PublicKey,
};
use skarbiec_crypto::openpgp::message::{
    decrypt, decrypt_with_passphrase, recipients, seal_with_passphrase, DecryptionKey,
};
use skarbiec_crypto::openpgp::signature::{sign_cleartext, verify_cleartext};
use skarbiec_crypto::openpgp::Error;
use skarbiec_crypto::wipe::Secret;
use std::path::PathBuf;

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/openpgp")
        .join(name)
}
fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(path(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}
fn text(name: &str) -> String {
    std::fs::read_to_string(path(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The fixture's keys as gpg --with-colons -K listed them: for each key, its
/// primary fingerprint and keygrip and its subkey's fingerprint and keygrip.
struct Listed {
    uid: String,
    primary_fpr: String,
    primary_grip: String,
    sub_fpr: String,
    sub_grip: String,
}

fn listed() -> Vec<Listed> {
    let mut out: Vec<Listed> = Vec::new();
    let mut fprs: Vec<String> = Vec::new();
    let mut grips: Vec<String> = Vec::new();
    let mut uid = String::new();
    for line in text("keys.colons").lines() {
        let fields: Vec<&str> = line.split(':').collect();
        match fields[0] {
            "sec" if !fprs.is_empty() => {
                out.push(Listed {
                    uid: uid.clone(),
                    primary_fpr: fprs[0].clone(),
                    primary_grip: grips[0].clone(),
                    sub_fpr: fprs[1].clone(),
                    sub_grip: grips[1].clone(),
                });
                fprs.clear();
                grips.clear();
            }
            "fpr" => fprs.push(fields[9].to_string()),
            "grp" => grips.push(fields[9].to_string()),
            "uid" => uid = fields[9].to_string(),
            _ => {}
        }
    }
    out.push(Listed {
        uid,
        primary_fpr: fprs[0].clone(),
        primary_grip: grips[0].clone(),
        sub_fpr: fprs[1].clone(),
        sub_grip: grips[1].clone(),
    });
    out
}

fn stored_keys() -> Vec<PublicKey> {
    read_pubring_db(&bytes("pubring.db"))
        .expect("pubring.db reads")
        .iter()
        .flat_map(|k| parse_public_keys(&k.keyblock).expect("keyblock parses"))
        .collect()
}

fn decryption_key(name: &str, passphrase: Option<&[u8]>) -> DecryptionKey {
    let l = listed()
        .into_iter()
        .find(|l| l.uid == name)
        .expect("listed");
    let key =
        read_key_file(&text(&format!("{}.key", l.sub_grip)), passphrase).expect("key file opens");
    let public = stored_keys()
        .into_iter()
        .find(|k| k.fingerprint_hex() == l.primary_fpr)
        .expect("public key stored");
    let sub = public
        .subkeys
        .iter()
        .find(|s| to_hex(&s.fingerprint).eq_ignore_ascii_case(&l.sub_fpr))
        .expect("subkey");
    assert_eq!(
        key.public().expect("public point"),
        sub.x25519,
        "{name}: the key file's point is the subkey's"
    );
    DecryptionKey {
        subkey_body: sub.body.clone(),
        scalar: Secret::new(key.x25519_secret().expect("scalar").to_vec()),
    }
}

#[test]
fn keyboxd_database_and_fingerprints() {
    let keys = stored_keys();
    let listed = listed();
    assert_eq!(
        keys.len(),
        listed.len(),
        "every key gpg listed is in pubring.db"
    );
    for l in &listed {
        let key = keys
            .iter()
            .find(|k| k.fingerprint_hex() == l.primary_fpr)
            .unwrap_or_else(|| panic!("{} not in pubring.db", l.uid));
        assert_eq!(key.user_ids, vec![l.uid.clone()]);
        assert_eq!(key.subkeys.len(), 1);
        assert!(
            to_hex(&key.subkeys[0].fingerprint).eq_ignore_ascii_case(&l.sub_fpr),
            "{}: subkey fingerprint",
            l.uid
        );
        assert_eq!(
            (key.subkeys[0].kdf_hash, key.subkeys[0].kdf_cipher),
            (8, 7),
            "{}: SHA-256 and AES-128",
            l.uid
        );
    }
}

/// A database cut inside its header is refused, not indexed past its end,
/// and every single-byte change of the real database is either read or
/// refused with a cause: none panics, loops or allocates without bound.
#[test]
fn crafted_keyboxd_databases_are_refused() {
    let real = bytes("pubring.db");
    for length in [16, 18, 19, 20, 21, 99] {
        let Err(error) = read_pubring_db(&real[..length]) else {
            panic!("a database cut to {length} bytes was read");
        };
        let error = error.to_string();
        assert!(!error.is_empty(), "{length} bytes");
    }
    let pages = real.len() / 4096;
    for page in 0..pages {
        let base = page * 4096 + if page == 0 { 100 } else { 0 };
        for offset in 0..16 {
            for value in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut changed = real.clone();
                changed[base + offset] = value;
                // Read or refused; either way it returns.
                let _outcome = read_pubring_db(&changed).map(|keys| keys.len());
            }
        }
    }
}

#[test]
fn armored_public_keys_match_the_database_and_verify() {
    let stored = stored_keys();
    for name in ["owner.pub.asc", "protected.pub.asc", "legacy.pub.asc"] {
        let data = dearmor(&text(name), "PGP PUBLIC KEY BLOCK").expect("armor");
        let key = &parse_public_keys(&data).expect("parses")[0];
        assert!(
            stored.iter().any(|s| s.fingerprint == key.fingerprint),
            "{name} is in pubring.db"
        );
        verify_self_signatures(&data).unwrap_or_else(|e| panic!("{name} self-signatures: {e}"));
    }
    assert_eq!(
        dearmor(&text("owner.pub.asc"), "PGP PUBLIC KEY BLOCK").expect("armor"),
        bytes("owner.pub.gpg")
    );
}

#[test]
fn agent_key_files() {
    for l in listed() {
        for grip in [&l.primary_grip, &l.sub_grip] {
            let file = text(&format!("{grip}.key"));
            if l.uid == "fixture-protected" {
                assert!(is_protected(&file));
                assert!(matches!(
                    read_key_file(&file, None),
                    Err(Error::BadPassphrase)
                ));
                assert!(matches!(
                    read_key_file(&file, Some(b"wrong")),
                    Err(Error::BadPassphrase)
                ));
                read_key_file(&file, Some(b"fixture phrase")).expect("opens with its phrase");
            } else {
                read_key_file(&file, None).expect("an unprotected key reads");
            }
        }
        let primary = read_key_file(
            &text(&format!("{}.key", l.primary_grip)),
            Some(b"fixture phrase"),
        )
        .expect("primary");
        let seed = primary.ed25519_seed().expect("Ed25519");
        let public = stored_keys()
            .into_iter()
            .find(|k| k.fingerprint_hex() == l.primary_fpr)
            .expect("stored");
        assert_eq!(
            skarbiec_crypto::ed25519::public_key(&seed),
            public.ed25519,
            "{}: the seed is the primary key's",
            l.uid
        );
    }
}

/// A key file that states an S2K count past what RFC 4880 can code is
/// refused before any hashing, and one nested far deeper than gpg-agent
/// writes is refused without recursing into it.
#[test]
fn crafted_agent_key_files_are_refused() {
    let file = text("79E8078C36DD38F98299FC076FF93136EB1B7EBF.key");
    assert!(
        file.contains("\"48628736\""),
        "the fixture states its count"
    );
    let endless = file.replace("\"48628736\"", "\"1152921504606846976\"");
    let Err(error) = read_key_file(&endless, Some(b"fixture phrase")) else {
        panic!("a key file with a count past RFC 4880's was read");
    };
    let error = error.to_string();
    assert!(
        error.contains("past the 65011712 RFC 4880 can state"),
        "{error}"
    );
    let deep = format!("Key: {}{}", "(".repeat(100_000), ")".repeat(100_000));
    let Err(error) = read_key_file(&deep, None) else {
        panic!("a key file nested 100,000 lists deep was read");
    };
    let error = error.to_string();
    assert!(error.contains("nests more than"), "{error}");
    let canonical = format!("{}{}", "(".repeat(100_000), ")".repeat(100_000));
    assert!(skarbiec_crypto::openpgp::agent::parse_canonical(canonical.as_bytes()).is_err());
    assert!(skarbiec_crypto::openpgp::agent::parse_canonical(b"(18446744073709551615:x)").is_err());
}

#[test]
fn messages_written_by_gnupg_open() {
    let expected = bytes("item.json");
    let owner = decryption_key("fixture-owner", None);
    let protected = decryption_key("fixture-protected", Some(b"fixture phrase"));
    let legacy = decryption_key("fixture-legacy", None);
    for (name, key) in [
        ("aead-ocb.asc", &owner),
        ("two-recipients.asc", &owner),
        ("two-recipients.asc", &protected),
        ("seipd-mdc.asc", &legacy),
    ] {
        let message = dearmor(&text(name), "PGP MESSAGE").expect("armor");
        let plain =
            decrypt(&message, std::slice::from_ref(key)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(plain.expose(), expected.as_slice(), "{name}");
    }
    let large = bytes("large.txt");
    assert_eq!(
        decrypt(&bytes("large-aead.gpg"), std::slice::from_ref(&owner))
            .expect("large OCB")
            .expose(),
        large.as_slice()
    );
    assert_eq!(
        decrypt(&bytes("large-seipd.gpg"), std::slice::from_ref(&legacy))
            .expect("large CFB")
            .expose(),
        large.as_slice()
    );
    let two = dearmor(&text("two-recipients.asc"), "PGP MESSAGE").expect("armor");
    assert_eq!(
        recipients(&two).expect("ids"),
        vec![owner.key_id(), protected.key_id()]
    );
}

#[test]
fn damaged_messages_are_refused() {
    let owner = decryption_key("fixture-owner", None);
    let legacy = decryption_key("fixture-legacy", None);
    let message = dearmor(&text("aead-ocb.asc"), "PGP MESSAGE").expect("armor");
    let not_for_this_key = decrypt(&message, std::slice::from_ref(&legacy)).expect_err("wrong key");
    assert_eq!(not_for_this_key, Error::NoKey(vec![owner.key_id()]));
    assert_eq!(
        not_for_this_key.to_string(),
        format!(
            "no secret key held here opens this message; it is encrypted to key id(s) {}",
            owner.key_id()
        )
    );
    let mut changed = message.clone();
    let last = changed.len() - 30;
    changed[last] ^= 1;
    assert!(matches!(
        decrypt(&changed, std::slice::from_ref(&owner)),
        Err(Error::Integrity(_))
    ));
    let mut cut = message.clone();
    cut.truncate(message.len() - 5);
    assert!(decrypt(&cut, std::slice::from_ref(&owner)).is_err());
    let seipd = dearmor(&text("seipd-mdc.asc"), "PGP MESSAGE").expect("armor");
    let mut changed = seipd.clone();
    let at = changed.len() - 10;
    changed[at] ^= 1;
    let refused = decrypt(&changed, std::slice::from_ref(&legacy)).expect_err("changed CFB");
    assert!(
        refused
            .to_string()
            .contains("modification detection code does not match"),
        "{refused}"
    );
    let mut armor_text = text("aead-ocb.asc");
    let body_at = armor_text.find("\n\n").expect("blank line") + 4;
    armor_text.replace_range(body_at..body_at + 1, "A");
    assert!(matches!(
        dearmor(&armor_text, "PGP MESSAGE"),
        Err(Error::Armor(_))
    ));
}

#[test]
fn passphrase_sealed_messages() {
    for name in ["symmetric-default.asc", "symmetric-rfc4880.asc"] {
        let message = dearmor(&text(name), "PGP MESSAGE").expect("armor");
        assert_eq!(
            decrypt_with_passphrase(&message, b"send phrase")
                .expect(name)
                .expose(),
            bytes("sealed.txt").as_slice(),
            "{name}"
        );
        assert_eq!(
            decrypt_with_passphrase(&message, b"other phrase").expect_err("wrong phrase"),
            Error::BadPassphrase,
            "{name}"
        );
    }
    let sealed = seal_with_passphrase(b"round trip", b"value").expect("seal");
    assert_eq!(
        decrypt_with_passphrase(&sealed, b"round trip")
            .expect("opens")
            .expose(),
        b"value"
    );
}

#[test]
fn cleartext_signatures() {
    let keys = stored_keys();
    let verified = verify_cleartext(&text("checkpoint.asc"), &keys)
        .expect("gpg's cleartext signature verifies");
    assert_eq!(verified, text("checkpoint.txt").trim_end_matches('\n'));
    let changed = text("checkpoint.asc").replace("generation 7", "generation 8");
    assert!(matches!(
        verify_cleartext(&changed, &keys),
        Err(Error::BadSignature(_))
    ));
    let l = listed()
        .into_iter()
        .find(|l| l.uid == "fixture-owner")
        .expect("owner");
    let seed = read_key_file(&text(&format!("{}.key", l.primary_grip)), None)
        .expect("key")
        .ed25519_seed()
        .expect("seed");
    let owner = keys
        .iter()
        .find(|k| k.fingerprint_hex() == l.primary_fpr)
        .expect("owner key");
    let ours = sign_cleartext(
        &seed,
        &owner.body,
        "epoch 3\n- dashed\ntrailing   ",
        1_700_000_000,
    );
    assert_eq!(
        verify_cleartext(&ours, &keys).expect("ours verifies"),
        "epoch 3\n- dashed\ntrailing   "
    );
}

#[test]
fn keys_we_write_verify_and_round_trip() {
    let seed = [7u8; 32];
    let x = skarbiec_crypto::x25519::public_key(&[9u8; 32]);
    let data = transferable_public_key(&seed, &x, "skarbiec-owner-test", 1_700_000_000);
    verify_self_signatures(&data).expect("our self-signatures verify");
    let key = &parse_public_keys(&data).expect("parses")[0];
    assert_eq!(key.user_ids, vec!["skarbiec-owner-test".to_string()]);
    assert_eq!(key.subkeys[0].x25519, x);
    let armored = armor(&data, "PGP PUBLIC KEY BLOCK");
    assert_eq!(
        dearmor(&armored, "PGP PUBLIC KEY BLOCK").expect("dearmor"),
        data
    );
    // What this crate writes for other OpenPGP programs to read is kept
    // under the test's target directory, so another implementation can be
    // pointed at the exact bytes: the key, a passphrase-sealed message
    // ("send phrase") and a cleartext signature by that key.
    let kept = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("openpgp-written");
    std::fs::create_dir_all(&kept).expect("evidence directory");
    let sealed =
        seal_with_passphrase(b"send phrase", b"sealed by skarbiec-crypto\n").expect("seal");
    let signed = sign_cleartext(&seed, &key.body, "signed by skarbiec-crypto", 1_700_000_000);
    for (name, content) in [
        ("key.asc", armored.into_bytes()),
        ("sealed.asc", armor(&sealed, "PGP MESSAGE").into_bytes()),
        ("signed.asc", signed.into_bytes()),
    ] {
        std::fs::write(kept.join(name), content).expect("evidence file");
    }
}

/// LibrePGP A.3.4/A.3.6: the sample OCB encrypted data packet opens with
/// the sample's session key and holds 'Hello, world!\n'.
#[test]
fn librepgp_ocb_sample() {
    let packet = hex(
        "d4 49 01 07 02 0e 5e d2 bc 1e 47 0a be 8f 1d 64 4c 7a 6c 8a 56 7b 0f 77 01 19 66 11 a1 54 ba 9c \
         25 74 cd 05 62 84 a8 ef 68 03 5c 62 3d 93 cc 70 8a 43 21 1b b6 ea f2 b2 7f 7c 18 d5 71 bc d8 3b \
         20 ad d3 a0 8b 73 af 15 b9 a0 98",
    );
    let cek = hex("d1 f0 1b a3 0e 13 0a a7 d2 58 2c 16 e0 50 ae 44");
    let opened =
        skarbiec_crypto::openpgp::message::open_ocb_packet(&packet[2..], &cek).expect("opens");
    assert_eq!(
        to_hex(&opened),
        "cb1462000000000048656c6c6f2c20776f726c64210a"
    );
}

#[test]
fn crc24_of_the_empty_string_is_its_initial_value() {
    assert_eq!(crc24(b""), 0x00b7_04ce);
}
