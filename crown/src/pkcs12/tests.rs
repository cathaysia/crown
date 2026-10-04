//! Unit tests for the PKCS#12 support.
//!
//! The fixtures under `tests/data/pki` were generated with the vendored
//! OpenSSL 3.5.8 CLI:
//!
//! ```text
//! openssl pkcs12 -export -inkey leaf.key -in leaf.pem -certfile ca.pem \
//!     -passout pass:crown-test                     # pfx_modern.p12 (PBES2)
//! openssl pkcs12 -export -legacy ...               # pfx_legacy.p12 (RC2/3DES)
//! openssl pkcs12 -export -nokeys -in leaf.pem ...  # pfx_nokey.p12
//! ```

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::asn1::pem;
use crate::pkcs12::{Bag, Pfx, SafeBag};
use crate::x509::cert::Certificate;
use crate::x509::keys::PrivateKeyInfo;

const PFX_MODERN: &[u8] = include_bytes!("../../tests/data/pki/pfx_modern.p12");
const PFX_LEGACY: &[u8] = include_bytes!("../../tests/data/pki/pfx_legacy.p12");
const PFX_NOKEY: &[u8] = include_bytes!("../../tests/data/pki/pfx_nokey.p12");
const RSA_PKCS8_PEM: &str = include_str!("../../tests/data/pki/rsa_pkcs8.pem");
const LEAF_PEM: &str = include_str!("../../tests/data/pki/leaf.pem");
const CA_PEM: &str = include_str!("../../tests/data/pki/ca.pem");

const PASSWORD: &[u8] = b"crown-test";

struct TestRng(u64);

impl crate::rng::Rng for TestRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (self.0 >> 33) as u8;
        }
    }
}

/// Decode a PFX into `(certificates, private key)`.
fn decode(pfx: &Pfx, password: &[u8]) -> (Vec<Certificate>, Option<PrivateKeyInfo>) {
    let mut certificates = Vec::new();
    let mut key = None;
    for bag in pfx.decoded_bags(password).unwrap() {
        match &bag.bag {
            Bag::ShroudedKey(info) => {
                key = Some(crate::x509::pbe::decrypt_private_key(info, password).unwrap());
            }
            Bag::Key(info) => key = Some(info.clone()),
            Bag::Cert(certificate) => certificates.push(certificate.clone()),
            _ => {}
        }
    }
    (certificates, key)
}

#[test]
fn modern_pfx_parses_and_decodes() {
    let pfx = Pfx::parse(PFX_MODERN).unwrap();
    assert_eq!(pfx.version, 3);
    assert!(pfx.mac.is_some());
    pfx.verify_mac(PASSWORD).unwrap();
    assert!(pfx.verify_mac(b"wrong").is_err());

    let (certificates, key) = decode(&pfx, PASSWORD);
    assert_eq!(certificates.len(), 2);
    let leaf = Certificate::from_pem(LEAF_PEM).unwrap();
    let ca = Certificate::from_pem(CA_PEM).unwrap();
    assert!(certificates
        .iter()
        .any(|cert| cert.encode() == leaf.encode()));
    assert!(certificates.iter().any(|cert| cert.encode() == ca.encode()));

    let key = key.unwrap();
    let expected = {
        let block = pem::parse_first(RSA_PKCS8_PEM).unwrap();
        PrivateKeyInfo::parse(&block.data).unwrap()
    };
    assert_eq!(key.encode(), expected.encode());

    // localKeyId attributes survive (OpenSSL's modern export does not set
    // friendlyName).
    let bags = pfx.decoded_bags(PASSWORD).unwrap();
    assert!(bags.iter().any(|bag| bag.local_key_id().is_some()));
    // Round-trip the container.
    let reparsed = Pfx::parse(&pfx.encode()).unwrap();
    reparsed.verify_mac(PASSWORD).unwrap();
    assert_eq!(reparsed.encode(), pfx.encode());
}

#[test]
fn legacy_pfx_parses_and_decodes() {
    let pfx = Pfx::parse(PFX_LEGACY).unwrap();
    assert_eq!(pfx.version, 3);
    pfx.verify_mac(PASSWORD).unwrap();
    assert!(pfx.verify_mac(b"wrong").is_err());
    let (certificates, key) = decode(&pfx, PASSWORD);
    assert_eq!(certificates.len(), 2);
    let key = key.unwrap();
    let expected = {
        let block = pem::parse_first(RSA_PKCS8_PEM).unwrap();
        PrivateKeyInfo::parse(&block.data).unwrap()
    };
    assert_eq!(key.encode(), expected.encode());
    let decoded = key.decode().unwrap();
    assert!(decoded.public_key().is_ok());
}

#[test]
fn certs_only_pfx_parses() {
    let pfx = Pfx::parse(PFX_NOKEY).unwrap();
    pfx.verify_mac(PASSWORD).unwrap();
    let (certificates, key) = decode(&pfx, PASSWORD);
    assert_eq!(certificates.len(), 1);
    assert!(key.is_none());
}

#[test]
fn tampered_pfx_mac_fails() {
    let mut der = PFX_MODERN.to_vec();
    // Flip a byte inside the authSafe content (well past the header).
    let position = der.len() / 2;
    der[position] ^= 0x01;
    let pfx = Pfx::parse(&der).unwrap();
    let result = pfx.verify_mac(PASSWORD);
    assert!(result.is_err());
}

#[test]
fn built_pfx_roundtrips() {
    let key_info = {
        let block = pem::parse_first(RSA_PKCS8_PEM).unwrap();
        PrivateKeyInfo::parse(&block.data).unwrap()
    };
    let leaf = Certificate::from_pem(LEAF_PEM).unwrap();
    let ca = Certificate::from_pem(CA_PEM).unwrap();
    let local_key_id = leaf.tbs().subject_key_identifier().unwrap();
    let mut rng = TestRng(41);

    let key_bag = Pfx::shrouded_key_bag(
        &key_info,
        PASSWORD,
        Some("leaf.crown.example"),
        &local_key_id,
        2048,
        &mut rng,
    )
    .unwrap();
    let leaf_bag = Pfx::certificate_bag(&leaf, Some("leaf.crown.example"), &local_key_id);
    let ca_bag = Pfx::certificate_bag(&ca, Some("Crown Test Root CA"), &[]);
    let pfx = Pfx::build(
        alloc::vec![key_bag, leaf_bag, ca_bag],
        PASSWORD,
        2048,
        &mut rng,
    )
    .unwrap();

    pfx.verify_mac(PASSWORD).unwrap();
    assert!(pfx.verify_mac(b"other").is_err());

    let reparsed = Pfx::parse(&pfx.encode()).unwrap();
    reparsed.verify_mac(PASSWORD).unwrap();
    let (certificates, key) = decode(&reparsed, PASSWORD);
    assert_eq!(certificates.len(), 2);
    assert_eq!(key.unwrap().encode(), key_info.encode());

    let bags: Vec<SafeBag> = reparsed.decoded_bags(PASSWORD).unwrap();
    let names: Vec<_> = bags.iter().filter_map(|bag| bag.friendly_name()).collect();
    assert!(names.contains(&"leaf.crown.example".to_string()));
    let leaf_bag = bags
        .iter()
        .find(|bag| bag.friendly_name().as_deref() == Some("leaf.crown.example"))
        .unwrap();
    assert_eq!(
        leaf_bag.local_key_id().as_deref(),
        Some(local_key_id.as_slice())
    );
}
