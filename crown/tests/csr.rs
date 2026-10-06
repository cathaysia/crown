//! PKCS#10 `extensionRequest` gate: parsing the requested extensions out of an
//! OpenSSL-generated CSR and carrying them into an issued certificate.
//!
//! The fixture was generated with the CLI as documented in
//! `tests/data/pki/pki_match_SOURCE.txt`.

use crown::asn1::pem;
use crown::asn1::time::Asn1Time;
use crown::x509::extensions::{key_usage, subject_alt_name, GeneralName, KeyUsage};
use crown::x509::keys::{PrivateKeyInfo, SubjectPublicKeyInfo};
use crown::x509::name::Name;
use crown::x509::{
    Certificate, CertificateBuilder, CertificationRequest, Hash, SignatureAlgorithm,
};

const CSR_PEM: &str = include_str!("data/pki/extreq.csr");
const SIGNING_KEY_PEM: &str = include_str!("data/pki/rsa_pkcs8.pem");

struct TestRng(u64);

impl crown::rng::Rng for TestRng {
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

fn signing_key() -> crown::x509::PrivateKey {
    let block = pem::parse_first(SIGNING_KEY_PEM).unwrap();
    PrivateKeyInfo::parse(&block.data)
        .unwrap()
        .decode()
        .unwrap()
}

#[test]
fn extension_request_parses_from_an_openssl_csr() {
    let csr = CertificationRequest::from_pem(CSR_PEM).expect("parse CSR");
    assert!(csr.verify_signature().unwrap(), "CSR self-signature");

    let extensions = csr.extensions().expect("extensionRequest parses");
    assert_eq!(extensions.len(), 4, "BC, KU, EKU and SAN requested");

    let by_oid = |arcs: &[u64]| {
        extensions
            .iter()
            .find(|extension| extension.oid.matches(arcs))
            .unwrap_or_else(|| panic!("extension {:?} absent", arcs))
    };

    let basic = by_oid(crown::asn1::oid::OID_BASIC_CONSTRAINTS);
    assert!(matches!(
        basic.parsed().unwrap(),
        crown::x509::ParsedExtension::BasicConstraints(constraints) if !constraints.ca
    ));

    let usage = by_oid(crown::asn1::oid::OID_KEY_USAGE);
    assert!(usage.critical);
    let crown::x509::ParsedExtension::KeyUsage(usage) = usage.parsed().unwrap() else {
        panic!("not keyUsage");
    };
    assert!(usage.digital_signature && usage.key_encipherment);
    assert!(!usage.key_cert_sign);

    let eku = by_oid(crown::asn1::oid::OID_EXTENDED_KEY_USAGE);
    let crown::x509::ParsedExtension::ExtendedKeyUsage(eku) = eku.parsed().unwrap() else {
        panic!("not extKeyUsage");
    };
    assert!(eku.contains(crown::asn1::oid::OID_KP_SERVER_AUTH));
    assert!(eku.contains(crown::asn1::oid::OID_KP_CLIENT_AUTH));

    let san = by_oid(crown::asn1::oid::OID_SUBJECT_ALT_NAME);
    let crown::x509::ParsedExtension::SubjectAltName(names) = san.parsed().unwrap() else {
        panic!("not subjectAltName");
    };
    assert!(matches!(&names[0], GeneralName::DnsName(name) if name == "req.crown.example"));
    assert!(matches!(&names[1], GeneralName::IpAddress(ip) if ip == &[10, 1, 2, 3]));

    // Rebuilding the extensionRequest attribute reproduces the original bytes.
    let rebuilt = crown::x509::attribute::extension_request(&extensions);
    let original = csr
        .info()
        .attributes
        .iter()
        .find(|attribute| {
            attribute
                .oid
                .matches(crown::asn1::oid::OID_PKCS9_EXTENSION_REQUEST)
        })
        .expect("extensionRequest attribute");
    assert_eq!(rebuilt.encode(), original.encode());
}

#[test]
fn certificates_can_carry_the_requested_extensions() {
    let csr = CertificationRequest::from_pem(CSR_PEM).unwrap();
    let key = signing_key();
    let mut rng = TestRng(0xc5);

    let builder =
        CertificateBuilder::from_request(&csr, SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256))
            .request_extensions(&csr)
            .expect("request extensions carry over")
            .issuer(Name::from_common_name("Crown Fixture Root CA"))
            .serial(vec![0x10])
            .validity(
                Asn1Time::from_unix(1_700_000_000, true),
                Asn1Time::from_unix(2_100_000_000, true),
            );
    assert_eq!(builder.extensions.len(), 4);
    let issued = builder.sign(&key, &mut rng).expect("issue");

    // The issued certificate has the requested SAN and key usage.
    let names = issued.tbs().subject_alt_names().expect("SAN on the cert");
    assert!(names
        .iter()
        .any(|name| matches!(name, GeneralName::DnsName(dns) if dns == "req.crown.example")));
    let usage = issued.tbs().key_usage().expect("keyUsage on the cert");
    assert!(usage.digital_signature && usage.key_encipherment);

    // The issued certificate verifies with the signing key and round-trips.
    assert!(issued.verify_signature(&key.public_key().unwrap()).unwrap());
    let reparsed = Certificate::parse(&issued.encode()).unwrap();
    assert_eq!(reparsed.encode(), issued.encode());

    // A hand-built extensionRequest attribute round-trips through its DER.
    let extensions = vec![
        key_usage(KeyUsage {
            digital_signature: true,
            ..Default::default()
        }),
        subject_alt_name(&[String::from("manual.crown.example")], &[]),
    ];
    let attribute = crown::x509::attribute::extension_request(&extensions);
    let encoded = attribute.encode();
    let mut reader = crown::asn1::der::Reader::new(&encoded);
    let reparsed_attribute = crown::x509::Attribute::parse(&mut reader).unwrap();
    let parsed = crown::x509::attribute::parse_extension_request(&reparsed_attribute).unwrap();
    assert_eq!(parsed.len(), 2);
    for (parsed, original) in parsed.iter().zip(extensions.iter()) {
        assert_eq!(parsed.oid, original.oid);
        assert_eq!(parsed.critical, original.critical);
        assert_eq!(parsed.value, original.value);
    }
}

#[test]
fn subject_public_key_info_survives_the_carry_over() {
    let csr = CertificationRequest::from_pem(CSR_PEM).unwrap();
    let key = signing_key();
    let spki = SubjectPublicKeyInfo::from_public_key(&key.public_key().unwrap()).unwrap();
    let mut rng = TestRng(1);
    let issued =
        CertificateBuilder::from_request(&csr, SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256))
            .validity(
                Asn1Time::from_unix(1_700_000_000, true),
                Asn1Time::from_unix(2_100_000_000, true),
            )
            .sign(&key, &mut rng)
            .unwrap();
    // The certificate carries the CSR's public key, not the issuer's.
    assert_eq!(
        issued.subject_public_key_info().key,
        csr.info().subject_public_key_info.key
    );
    assert_ne!(issued.subject_public_key_info().key, spki.key);
}
