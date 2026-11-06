//! The sealed format: round trips to one and several recipients, each
//! recipient opening alone; a key that is not a recipient refused naming the
//! recipients; every byte changed in turn refused; a changed recipient list
//! refused; and an item sealed to a Curve25519 subkey gpg made opens with the
//! scalar from gpg-agent's key file, so a recipient keeps its identity.

use skarbiec_crypto::openpgp::agent::read_key_file;
use skarbiec_crypto::sealed::{is_sealed, key_id, open, recipients, seal, OpenError, MAGIC};
use skarbiec_crypto::x25519::public_key;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

#[test]
fn round_trip_to_several_recipients() {
    let secrets = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let publics: Vec<[u8; 32]> = secrets.iter().map(public_key).collect();
    let sealed = seal(&publics, b"{\"value\":\"secret\"}").expect("seal");
    assert!(is_sealed(&sealed) && sealed.starts_with(MAGIC));
    assert_eq!(
        recipients(&sealed).expect("ids"),
        publics.iter().map(|p| hex(&key_id(p))).collect::<Vec<_>>()
    );
    for secret in &secrets {
        assert_eq!(
            open(&sealed, std::slice::from_ref(secret))
                .expect("opens")
                .expose(),
            b"{\"value\":\"secret\"}"
        );
    }
    let stranger = [9u8; 32];
    let refused = open(&sealed, &[stranger]).expect_err("not a recipient");
    assert!(matches!(&refused, OpenError::NoKey(ids) if ids.len() == 3));
    assert!(refused.to_string().starts_with(
        "no key held here is a recipient of this sealed item; it is sealed to key id(s) "
    ));
}

/// An entry naming a held key that does not unwrap, put before the genuine
/// one for the same key, does not make the item read as forged: every entry
/// for the key is tried.
#[test]
fn a_bogus_entry_before_the_genuine_one_is_passed_over() {
    use skarbiec_crypto::chacha;
    use skarbiec_crypto::hmac::hkdf_sha256;
    use skarbiec_crypto::x25519::shared_secret;
    let secret = [7u8; 32];
    let public = public_key(&secret);
    let content_key = [11u8; 32];
    let ephemeral = [13u8; 32];
    let ephemeral_public = public_key(&ephemeral);
    let shared = shared_secret(&ephemeral, &public).expect("shared");
    let mut salt = ephemeral_public.to_vec();
    salt.extend_from_slice(&public);
    let wrapping: [u8; 32] = hkdf_sha256(&salt, &shared, b"skarbiec-sealed-1 wrap", 32)
        .expect("32")
        .try_into()
        .expect("32");
    let genuine = chacha::seal(&wrapping, &[0u8; 12], &[], &content_key);
    let mut out = MAGIC.to_vec();
    out.push(2);
    // First a bogus entry under the same key id, then the genuine one.
    out.extend_from_slice(&key_id(&public));
    out.extend_from_slice(&public_key(&[17u8; 32]));
    out.extend_from_slice(&vec![0u8; genuine.len()]);
    out.extend_from_slice(&key_id(&public));
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(&genuine);
    let header = out.clone();
    let nonce = [19u8; 12];
    out.extend_from_slice(&nonce);
    out.extend(chacha::seal(&content_key, &nonce, &header, b"held"));
    match open(&out, &[secret]) {
        Ok(plain) => assert_eq!(plain.expose(), b"held"),
        Err(error) => panic!("the genuine entry was not tried: {error}"),
    }
}

#[test]
fn every_changed_byte_is_refused() {
    let secret = [5u8; 32];
    let sealed = seal(&[public_key(&secret)], b"value").expect("seal");
    for at in MAGIC.len()..sealed.len() {
        let mut changed = sealed.clone();
        changed[at] ^= 0x01;
        let refused = open(&changed, &[secret]);
        assert!(refused.is_err(), "byte {at} changed still opened");
    }
    let mut not_sealed = sealed.clone();
    not_sealed[0] ^= 1;
    assert_eq!(
        open(&not_sealed, &[secret]).expect_err("magic"),
        OpenError::NotSealed
    );
    assert!(matches!(
        open(&sealed[..MAGIC.len() + 10], &[secret]),
        Err(OpenError::Malformed(_))
    ));
}

#[test]
fn a_recipient_cannot_be_dropped_or_swapped() {
    let (a, b) = ([1u8; 32], [2u8; 32]);
    let sealed = seal(&[public_key(&a), public_key(&b)], b"value").expect("seal");
    // Rewrite the header to name only the first recipient.
    let mut fewer = sealed[..MAGIC.len()].to_vec();
    fewer.push(1);
    fewer.extend_from_slice(&sealed[MAGIC.len() + 1..MAGIC.len() + 1 + 88]);
    fewer.extend_from_slice(&sealed[MAGIC.len() + 1 + 2 * 88..]);
    assert_eq!(
        open(&fewer, &[a]).expect_err("header changed"),
        OpenError::Forged
    );
}

#[test]
fn a_gnupg_curve25519_subkey_is_a_recipient() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/openpgp/BF25859AE157784A2D8599AEA5087DB65B8AC04F.key");
    let file = std::fs::read_to_string(path).expect("fixture key file");
    let key = read_key_file(&file, None).expect("reads");
    let scalar = key.x25519_secret().expect("Curve25519");
    let public = key.public().expect("point");
    assert_eq!(
        public_key(&scalar),
        public,
        "the key file's scalar is its public key's"
    );
    let sealed = seal(&[public], b"kept identity").expect("seal");
    assert_eq!(
        open(&sealed, &[scalar]).expect("opens").expose(),
        b"kept identity"
    );
}

#[test]
fn seal_refuses_no_recipients() {
    let refused = seal(&[], b"value").expect_err("none");
    assert_eq!(
        refused.to_string(),
        "a sealed item has 1 to 255 recipients, not 0"
    );
}
