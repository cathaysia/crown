//! Unit tests for the PKCS#7 / CMS support.
//!
//! The fixtures under `tests/data/pki` were generated with the vendored
//! OpenSSL 3.5.8 CLI:
//!
//! ```text
//! openssl cms -sign -in payload.txt -signer leaf.pem -inkey leaf.key \
//!     -certfile ca.pem -outform DER -nodetach -md sha256   # cms_attached.der
//! openssl cms -sign ... (detached)                         # cms_detached.der
//! openssl cms -sign -signer ec.pem -inkey ec.key -md sha384 # cms_ec.der
//! openssl crl2pkcs7 -nocrl -certfile leaf.pem -certfile ca.pem # p7c_certs.der
//! ```

use alloc::vec::Vec;

use crate::asn1::pem;
use crate::asn1::time::Asn1Time;
use crate::pkcs7::{ContentInfo, Pkcs7, SignedData, SignedDataBuilder, SignerIdentifier};
use crate::x509::algorithm::{Hash, SignatureAlgorithm};
use crate::x509::cert::Certificate;
use crate::x509::keys::{PrivateKey, PrivateKeyInfo};

const CMS_ATTACHED: &[u8] = include_bytes!("../../tests/data/pki/cms_attached.der");
const CMS_DETACHED: &[u8] = include_bytes!("../../tests/data/pki/cms_detached.der");
const CMS_EC: &[u8] = include_bytes!("../../tests/data/pki/cms_ec.der");
const P7C_CERTS: &[u8] = include_bytes!("../../tests/data/pki/p7c_certs.der");
const PAYLOAD: &[u8] = include_bytes!("../../tests/data/pki/payload.txt");
const LEAF_PEM: &str = include_str!("../../tests/data/pki/leaf.pem");
const CA_PEM: &str = include_str!("../../tests/data/pki/ca.pem");
const LEAF_KEY_PEM: &str = include_str!("../../tests/data/pki/rsa_pkcs8.pem");

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

fn leaf_key() -> PrivateKey {
    let block = pem::parse_first(LEAF_KEY_PEM).unwrap();
    PrivateKeyInfo::parse(&block.data)
        .unwrap()
        .decode()
        .unwrap()
}

#[test]
fn attached_signed_data_verifies() {
    let pkcs7 = Pkcs7::parse(CMS_ATTACHED).unwrap();
    let Pkcs7::SignedData(signed_data) = pkcs7 else {
        panic!("not signed data");
    };
    assert_eq!(signed_data.signer_infos.len(), 1);
    assert_eq!(signed_data.certificates.len(), 2);
    assert_eq!(
        signed_data.encap_content_info.content.as_deref(),
        Some(PAYLOAD)
    );
    // The digest algorithm is SHA-256 with absent parameters, as OpenSSL
    // emits.
    assert_eq!(
        signed_data.signer_infos[0].digest_algorithm.parameters,
        None
    );

    signed_data.verify(None).unwrap();

    // The signer certificate is the embedded leaf and it chains to the CA.
    let signer = &signed_data.signer_infos[0];
    let certificate = signed_data.certificate_for(&signer.sid).unwrap();
    assert_eq!(
        certificate.subject().common_name().unwrap(),
        "leaf.crown.example"
    );
    let ca = Certificate::from_pem(CA_PEM).unwrap();
    certificate.verify_signature(ca.public_key()).unwrap();

    // Tampering with the content must fail.
    let mut tampered = CMS_ATTACHED.to_vec();
    let position = tampered
        .windows(PAYLOAD.len())
        .position(|window| window == PAYLOAD)
        .unwrap();
    tampered[position] ^= 0x01;
    let tampered = Pkcs7::parse(&tampered).unwrap();
    let Pkcs7::SignedData(tampered) = tampered else {
        panic!("not signed data");
    };
    assert!(tampered.verify(None).is_err());
}

#[test]
fn detached_signed_data_verifies() {
    let Pkcs7::SignedData(signed_data) = Pkcs7::parse(CMS_DETACHED).unwrap() else {
        panic!("not signed data");
    };
    assert!(signed_data.encap_content_info.content.is_none());
    assert!(signed_data.verify(None).is_err());
    signed_data.verify(Some(PAYLOAD)).unwrap();
    assert!(signed_data.verify(Some(b"wrong payload")).is_err());
}

#[test]
fn ecdsa_signed_data_verifies() {
    let Pkcs7::SignedData(signed_data) = Pkcs7::parse(CMS_EC).unwrap() else {
        panic!("not signed data");
    };
    assert_eq!(
        signed_data.encap_content_info.content.as_deref(),
        Some(PAYLOAD)
    );
    signed_data.verify(None).unwrap();
}

#[test]
fn certs_only_pkcs7_parses() {
    let Pkcs7::SignedData(signed_data) = Pkcs7::parse(P7C_CERTS).unwrap() else {
        panic!("not signed data");
    };
    assert!(signed_data.signer_infos.is_empty());
    assert_eq!(signed_data.certificates.len(), 2);
    assert!(signed_data.verify(None).is_ok());
}

#[test]
fn built_signed_data_roundtrips_and_verifies() {
    let key = leaf_key();
    let leaf = Certificate::from_pem(LEAF_PEM).unwrap();
    let ca = Certificate::from_pem(CA_PEM).unwrap();
    let mut rng = TestRng(17);

    let signed_data = SignedDataBuilder::new(PAYLOAD.to_vec())
        .add_certificate(leaf.clone())
        .add_certificate(ca.clone())
        .signing_time(Asn1Time::from_unix(1_800_000_000, true))
        .sign(
            &key,
            &leaf,
            Hash::Sha256,
            SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
            &mut rng,
        )
        .unwrap();

    signed_data.verify(None).unwrap();
    let signer = &signed_data.signer_infos[0];
    assert!(matches!(
        &signer.sid,
        SignerIdentifier::IssuerAndSerialNumber { .. }
    ));
    let attributes = signer.signed_attrs.as_ref().unwrap();
    assert!(attributes
        .iter()
        .any(|attr| attr.oid.matches(crate::asn1::oid::OID_PKCS9_MESSAGE_DIGEST)));
    assert!(attributes
        .iter()
        .any(|attr| attr.oid.matches(crate::asn1::oid::OID_PKCS9_CONTENT_TYPE)));
    assert_eq!(attributes.len(), 3);

    // Parse the encoded form back and verify again.
    let encoded = signed_data.to_content_info().encode();
    let reparsed = Pkcs7::parse(&encoded).unwrap();
    let Pkcs7::SignedData(reparsed) = reparsed else {
        panic!("not signed data");
    };
    reparsed.verify(None).unwrap();
    assert_eq!(reparsed.certificates.len(), 2);

    // Signing over signed attributes means the content digest is covered:
    // replacing the content must fail.
    let mut modified = reparsed.clone();
    modified.encap_content_info.content = Some(b"replaced".to_vec());
    assert!(modified.verify(None).is_err());

    // Detached variant.
    let detached = SignedDataBuilder::detached(PAYLOAD.to_vec())
        .add_certificate(leaf.clone())
        .sign(
            &key,
            &leaf,
            Hash::Sha256,
            SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
            &mut rng,
        )
        .unwrap();
    detached.verify(Some(PAYLOAD)).unwrap();
    assert!(detached.verify(Some(b"other")).is_err());
}

#[test]
fn built_ecdsa_signed_data_roundtrips() {
    let ec_key_pem = include_str!("../../tests/data/pki/ec_pkcs8.pem");
    let block = pem::parse_first(ec_key_pem).unwrap();
    let key = PrivateKeyInfo::parse(&block.data)
        .unwrap()
        .decode()
        .unwrap();
    let leaf = Certificate::from_pem(include_str!("../../tests/data/pki/ec.pem")).unwrap();
    let mut rng = TestRng(23);
    let signed_data = SignedDataBuilder::new(PAYLOAD.to_vec())
        .add_certificate(leaf.clone())
        .sign(
            &key,
            &leaf,
            Hash::Sha384,
            SignatureAlgorithm::Ecdsa(Hash::Sha384),
            &mut rng,
        )
        .unwrap();
    let reparsed = SignedData::parse(&signed_data.encode()).unwrap();
    reparsed.verify(None).unwrap();
}

#[test]
fn tampered_signature_is_rejected() {
    let Pkcs7::SignedData(mut signed_data) = Pkcs7::parse(CMS_ATTACHED).unwrap() else {
        panic!("not signed data");
    };
    let last = signed_data.signer_infos[0].signature.len() - 1;
    signed_data.signer_infos[0].signature[last] ^= 0x01;
    assert!(signed_data.verify(None).is_err());
}

#[test]
fn content_info_roundtrip() {
    let info = ContentInfo::data(b"hello");
    let encoded = info.encode();
    let reparsed = Pkcs7::parse(&encoded).unwrap();
    let Pkcs7::Data(content) = reparsed else {
        panic!("not data");
    };
    assert_eq!(content, b"hello");
    assert_eq!(
        info.content_type.matches(crate::asn1::oid::OID_PKCS7_DATA),
        true
    );
}
