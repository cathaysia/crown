//! Unit tests for the X.509 / PKCS support.
//!
//! The fixtures under `tests/data/pki` were generated with the vendored
//! OpenSSL 3.5.8 CLI (see `docs/algorithms-status.md` section 3):
//!
//! ```text
//! openssl req -x509 -newkey rsa:2048 ...            # ca.pem (CA:TRUE, pathlen:1)
//! openssl x509 -req -CA ca.pem -CAkey ca.key ...    # leaf.pem (SAN/KU/EKU/AKI)
//! openssl req -x509 -newkey ec|ed25519|...          # ec/ed/sm2/mldsa/slhdsa
//! openssl ca -gencrl                                # crl.pem
//! openssl pkcs8 -topk8 [-v1 PBE-SHA1-3DES] ...      # *pkcs8*.pem (pass: crown-test)
//! ```

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::asn1::der::Reader;
use crate::asn1::oid;
use crate::asn1::pem;
use crate::asn1::time::Asn1Time;
use crate::x509::algorithm::{Hash, SignatureAlgorithm};
use crate::x509::cert::{Certificate, CertificateBuilder};
use crate::x509::crl::{CertificateList, RevokedCertificate};
use crate::x509::csr::CertificationRequest;
use crate::x509::extensions::{
    basic_constraints, extended_key_usage, key_usage, subject_alt_name, GeneralName, KeyUsage,
};
use crate::x509::keys::{
    EncryptedPrivateKeyInfo, PrivateKey, PrivateKeyInfo, PublicKey, SubjectPublicKeyInfo,
};
use crate::x509::name::Name;

const CA_PEM: &str = include_str!("../../tests/data/pki/ca.pem");
const LEAF_PEM: &str = include_str!("../../tests/data/pki/leaf.pem");
const LEAF_CSR_PEM: &str = include_str!("../../tests/data/pki/leaf.csr");
const EC_PEM: &str = include_str!("../../tests/data/pki/ec.pem");
const ED_PEM: &str = include_str!("../../tests/data/pki/ed.pem");
const SM2_PEM: &str = include_str!("../../tests/data/pki/sm2.pem");
const SM2_STDID_PEM: &str = include_str!("../../tests/data/pki/sm2_stdid.pem");
const MLDSA_PEM: &str = include_str!("../../tests/data/pki/mldsa.pem");
const SLHDSA_PEM: &str = include_str!("../../tests/data/pki/slhdsa.pem");
const CRL_PEM: &str = include_str!("../../tests/data/pki/crl.pem");
const POLICIES_PEM: &str = include_str!("../../tests/data/pki/policies.pem");
const CRLDP_PEM: &str = include_str!("../../tests/data/pki/crldp.pem");
const RSA_PKCS8_PEM: &str = include_str!("../../tests/data/pki/rsa_pkcs8.pem");
const RSA_PKCS8_PBES2_PEM: &str = include_str!("../../tests/data/pki/rsa_pkcs8_pbes2.pem");
const RSA_PKCS8_3DES_PEM: &str = include_str!("../../tests/data/pki/rsa_pkcs8_3des.pem");
const EC_PKCS8_PEM: &str = include_str!("../../tests/data/pki/ec_pkcs8.pem");
const ED_PKCS8_PEM: &str = include_str!("../../tests/data/pki/ed_pkcs8.pem");
const SM2_PKCS8_PEM: &str = include_str!("../../tests/data/pki/sm2_pkcs8.pem");
const MLDSA_PKCS8_PEM: &str = include_str!("../../tests/data/pki/mldsa_pkcs8.pem");
const EC_PKCS8_PBES2_PEM: &str = include_str!("../../tests/data/pki/ec_pkcs8_pbes2.pem");

const PASSWORD: &[u8] = b"crown-test";

/// A deterministic RNG for signing tests.
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

fn cert(pem_text: &str) -> Certificate {
    Certificate::from_pem(pem_text).unwrap()
}

fn der_of(pem_text: &str) -> Vec<u8> {
    pem::parse_first(pem_text).unwrap().data
}

fn private_key(pem_text: &str) -> PrivateKey {
    let block = pem::parse_first(pem_text).unwrap();
    let info = PrivateKeyInfo::parse(&block.data).unwrap();
    info.decode().unwrap()
}

/// `(algorithm, key)` from a PKCS#8 public/private pair.
fn key_pair(key_pem: &str) -> (PrivateKey, PublicKey) {
    let key = private_key(key_pem);
    let public = key.public_key().unwrap();
    (key, public)
}

#[test]
fn rsa_chain_parses_and_verifies() {
    let ca = cert(CA_PEM);
    let leaf = cert(LEAF_PEM);

    assert_eq!(ca.tbs().version, 2);
    assert!(ca.tbs().is_ca());
    assert_eq!(ca.tbs().basic_constraints().unwrap().path_len, Some(1));
    assert_eq!(ca.subject().common_name().unwrap(), "Crown Test Root CA");
    assert_eq!(ca.subject().country().unwrap(), "CN");
    assert_eq!(
        ca.subject().to_string(),
        "C=CN,O=Crown Test,CN=Crown Test Root CA"
    );
    assert!(ca.is_self_signed());
    assert!(ca.verify_signature(ca.public_key()).unwrap());

    assert_eq!(leaf.subject().common_name().unwrap(), "leaf.crown.example");
    assert_eq!(leaf.issuer().common_name().unwrap(), "Crown Test Root CA");
    assert!(!leaf.tbs().is_ca());
    assert!(leaf.verify_signature(ca.public_key()).unwrap());

    // Extension decoding.
    let san = leaf.tbs().subject_alt_names().unwrap();
    assert_eq!(san.len(), 3);
    assert!(matches!(&san[0], GeneralName::DnsName(name) if name == "leaf.crown.example"));
    assert!(matches!(&san[1], GeneralName::DnsName(name) if name == "alt.crown.example"));
    assert!(matches!(&san[2], GeneralName::IpAddress(ip) if ip == &[127, 0, 0, 1]));
    let ku = leaf.tbs().key_usage().unwrap();
    assert!(ku.digital_signature && ku.key_encipherment);
    assert!(!ku.key_cert_sign);
    let eku = leaf.tbs().extended_key_usage().unwrap();
    assert!(eku.contains(oid::OID_KP_SERVER_AUTH));
    assert!(eku.contains(oid::OID_KP_CLIENT_AUTH));
    assert!(!eku.contains(oid::OID_KP_CODE_SIGNING));
    assert!(leaf.tbs().subject_key_identifier().is_some());
    assert!(leaf.tbs().authority_key_identifier().is_some());

    // Chain verification with an explicit "now" inside the validity window.
    let now = 1_800_000_000; // 2027-01
    assert!(leaf.verify(&ca, Some(now)).is_ok());
    // A time before the certificate exists must fail.
    assert!(leaf.verify(&ca, Some(0)).is_err());

    // Re-encoding is byte-exact.
    assert_eq!(leaf.encode(), der_of(LEAF_PEM));
    assert_eq!(ca.encode(), der_of(CA_PEM));
}

#[test]
fn self_signed_algorithms_verify() {
    let cases: [(&str, &str); 5] = [
        ("ec", EC_PEM),
        ("ed", ED_PEM),
        ("sm2-stdid", SM2_STDID_PEM),
        ("mldsa", MLDSA_PEM),
        ("slhdsa", SLHDSA_PEM),
    ];
    let mut checked = 0;
    for (name, pem_text) in cases {
        let certificate = cert(pem_text);
        assert!(certificate.is_self_signed(), "{name}: not self-signed");
        assert!(
            certificate
                .verify_signature(certificate.public_key())
                .unwrap(),
            "{name}: self-signature did not verify"
        );
        assert_eq!(certificate.encode(), der_of(pem_text), "{name}: re-encode");
        assert_eq!(certificate.to_pem(), pem_text, "{name}: PEM roundtrip");
        checked += 1;
    }
    assert!(checked >= 5, "only {checked} algorithms verified");

    // OpenSSL's provider CLI signs SM2 with an empty ID unless `distid` is
    // set, so that fixture verifies only through the explicit-ID API; the
    // default (GM/T) identity must not verify it.
    let open_ssl_default = cert(SM2_PEM);
    assert!(open_ssl_default
        .verify_signature_with_sm2_id(open_ssl_default.public_key(), b"")
        .unwrap());
    assert!(!open_ssl_default
        .verify_signature(open_ssl_default.public_key())
        .unwrap());
}

#[test]
fn tampered_signature_is_rejected() {
    let ca = cert(CA_PEM);
    let mut der = der_of(LEAF_PEM);
    let last = der.len() - 1;
    der[last] ^= 0x01;
    let tampered = Certificate::parse(&der).unwrap();
    let result = tampered.verify_signature(ca.public_key());
    assert!(result.is_err() || !result.unwrap());
}

#[test]
fn csr_parses_verifies_and_builds() {
    let csr = CertificationRequest::from_pem(LEAF_CSR_PEM).unwrap();
    assert_eq!(csr.info().version, 0);
    assert_eq!(
        csr.info().subject.common_name().unwrap(),
        "leaf.crown.example"
    );
    assert!(csr.verify_signature().unwrap());
    assert_eq!(csr.encode(), der_of(LEAF_CSR_PEM));

    // Build one with our own key.
    let (key, public) = key_pair(EC_PKCS8_PEM);
    let spki = SubjectPublicKeyInfo::from_public_key(&public).unwrap();
    let mut rng = TestRng(42);
    let built = CertificationRequest::build(
        Name::from_common_name("built.crown.example"),
        spki,
        Vec::new(),
        SignatureAlgorithm::Ecdsa(Hash::Sha256),
        &key,
        &mut rng,
    )
    .unwrap();
    assert!(built.verify_signature().unwrap());
    let reparsed = CertificationRequest::parse(&built.encode()).unwrap();
    assert!(reparsed.verify_signature().unwrap());
    assert_eq!(
        reparsed.info().subject.common_name().unwrap(),
        "built.crown.example"
    );
}

#[test]
fn crl_parses_and_verifies() {
    let ca = cert(CA_PEM);
    let crl = CertificateList::from_pem(CRL_PEM).unwrap();
    assert_eq!(crl.tbs().issuer, ca.tbs().subject);
    assert!(crl.verify_signature(ca.public_key()).unwrap());
    assert_eq!(crl.encode(), der_of(CRL_PEM));
    assert_eq!(crl.to_pem(), CRL_PEM);
    // The freshly generated CRL has no revoked entries.
    assert!(crl.tbs().revoked_certificates.is_empty());
    assert!(crl.is_revoked(&[0x01]).is_none());

    // A CRL we build ourselves is verifiable.
    let (key, _) = key_pair(RSA_PKCS8_PEM);
    let mut rng = TestRng(7);
    let built = CertificateList::build(
        ca.tbs().subject.clone(),
        Asn1Time::from_unix(1_800_000_000, true),
        Some(Asn1Time::from_unix(1_802_000_000, true)),
        alloc::vec![RevokedCertificate {
            serial_number: alloc::vec![0x2a],
            revocation_date: Asn1Time::from_unix(1_790_000_000, true),
            extensions: Vec::new(),
        }],
        Vec::new(),
        SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
        &key,
        &mut rng,
    )
    .unwrap();
    let signer = key.public_key().unwrap();
    assert!(built.verify_signature(&signer).unwrap());
    assert!(built.is_revoked(&[0x2a]).is_some());
    let reparsed = CertificateList::parse(&built.encode()).unwrap();
    assert!(reparsed.verify_signature(&signer).unwrap());
    assert_eq!(reparsed.tbs().revoked_certificates.len(), 1);
}

#[test]
fn pkcs8_keys_decode_to_matching_public_keys() {
    assert_eq!(
        private_key(RSA_PKCS8_PEM)
            .public_key()
            .unwrap()
            .to_algorithm_and_key()
            .unwrap(),
        cert(LEAF_PEM).public_key().to_algorithm_and_key().unwrap()
    );
    let cases: [(&str, &str, &str); 4] = [
        ("ec", EC_PKCS8_PEM, EC_PEM),
        ("ed", ED_PKCS8_PEM, ED_PEM),
        ("sm2", SM2_PKCS8_PEM, SM2_PEM),
        ("mldsa", MLDSA_PKCS8_PEM, MLDSA_PEM),
    ];
    let mut checked = 0;
    for (name, key_pem, cert_pem) in cases {
        let key = private_key(key_pem);
        let expected = cert(cert_pem);
        assert_eq!(
            key.public_key().unwrap().to_algorithm_and_key().unwrap(),
            expected.public_key().to_algorithm_and_key().unwrap(),
            "{name}: private key does not match certificate"
        );
        checked += 1;
    }
    assert!(checked >= 4, "only {checked} key pairs checked");
}

#[test]
fn pkcs8_encrypted_keys_decrypt() {
    for (name, pem_text) in [
        ("pbes2-rsa", RSA_PKCS8_PBES2_PEM),
        ("pbes2-ec", EC_PKCS8_PBES2_PEM),
        ("legacy-3des", RSA_PKCS8_3DES_PEM),
    ] {
        let block = pem::parse_first(pem_text).unwrap();
        assert_eq!(block.label, "ENCRYPTED PRIVATE KEY");
        let info = EncryptedPrivateKeyInfo::parse(&block.data).unwrap();
        let decrypted = crate::x509::pbe::decrypt_private_key(&info, PASSWORD).unwrap();
        let key = decrypted.decode().unwrap();
        assert!(
            key.public_key().is_ok(),
            "{name}: decrypted key did not decode"
        );
        // Wrong password must fail (never silently succeed).
        let wrong = crate::x509::pbe::decrypt_private_key(&info, b"wrong");
        assert!(wrong.is_err(), "{name}: wrong password accepted");
    }

    // The PBES2-encrypted RSA key must equal the plaintext one.
    let block = pem::parse_first(RSA_PKCS8_PBES2_PEM).unwrap();
    let info = EncryptedPrivateKeyInfo::parse(&block.data).unwrap();
    let decrypted = crate::x509::pbe::decrypt_private_key(&info, PASSWORD).unwrap();
    assert_eq!(
        decrypted
            .decode()
            .unwrap()
            .public_key()
            .unwrap()
            .to_algorithm_and_key()
            .unwrap(),
        private_key(RSA_PKCS8_PEM)
            .public_key()
            .unwrap()
            .to_algorithm_and_key()
            .unwrap()
    );
}

#[test]
fn encrypted_key_roundtrip_through_our_encoder() {
    let key = private_key(EC_PKCS8_PEM);
    let PrivateKey::Ec { scalar, .. } = &key else {
        unreachable!()
    };
    let point = match key.public_key().unwrap() {
        PublicKey::Ec { point, .. } => point.to_bytes(),
        _ => unreachable!(),
    };
    let ec_key =
        crate::x509::keys::encode_ec_private_key(oid::OID_SECP256R1, scalar, Some(&point)).unwrap();
    let info = PrivateKeyInfo {
        algorithm: crate::x509::algorithm::AlgorithmIdentifier::new(
            crate::asn1::oid::ObjectIdentifier::new(oid::OID_EC_PUBLIC_KEY).unwrap(),
            Some(crate::asn1::der::oid(
                &crate::asn1::oid::ObjectIdentifier::new(oid::OID_SECP256R1).unwrap(),
            )),
        ),
        private_key: ec_key,
        attributes: None,
        public_key: Some(point),
    };
    let mut rng = TestRng(11);
    let encrypted = crate::x509::pbe::encrypt_private_key(
        &info.encode(),
        PASSWORD,
        crate::x509::pbe::Pbes2Cipher::Aes256Cbc { iv: Vec::new() },
        2048,
        &mut rng,
    )
    .unwrap();
    let decrypted = crate::x509::pbe::decrypt_private_key(&encrypted, PASSWORD).unwrap();
    let decoded = decrypted.decode().unwrap();
    assert_eq!(
        decoded
            .public_key()
            .unwrap()
            .to_algorithm_and_key()
            .unwrap(),
        key.public_key().unwrap().to_algorithm_and_key().unwrap()
    );
    // Roundtrip the EncryptedPrivateKeyInfo container itself.
    let reparsed = EncryptedPrivateKeyInfo::parse(&encrypted.encode()).unwrap();
    assert_eq!(reparsed.algorithm, encrypted.algorithm);
}

#[test]
fn certificate_builder_signs_and_parses() {
    let (key, public) = key_pair(EC_PKCS8_PEM);
    let subject = Name::from_common_name("builder.crown.example");
    let spki = SubjectPublicKeyInfo::from_public_key(&public).unwrap();
    let mut builder = CertificateBuilder::new(
        subject.clone(),
        spki,
        SignatureAlgorithm::Ecdsa(Hash::Sha256),
    );
    builder = builder
        .serial(alloc::vec![0x01, 0x00])
        .validity(
            Asn1Time::from_unix(1_700_000_000, true),
            Asn1Time::from_unix(2_000_000_000, true),
        )
        .extension(basic_constraints(true, Some(0)))
        .extension(key_usage(KeyUsage {
            key_cert_sign: true,
            crl_sign: true,
            ..Default::default()
        }))
        .extension(subject_alt_name(
            &["builder.crown.example".to_string()],
            &[[10, 0, 0, 1]],
        ))
        .extension(extended_key_usage(&[oid::OID_KP_SERVER_AUTH]));
    let mut rng = TestRng(3);
    let built = builder.sign(&key, &mut rng).unwrap();

    assert!(built.verify_signature(built.public_key()).unwrap());
    assert_eq!(built.serial_number(), &[0x01, 0x00]);
    assert!(built.tbs().is_ca());
    assert_eq!(built.tbs().basic_constraints().unwrap().path_len, Some(0));
    let san = built.tbs().subject_alt_names().unwrap();
    assert_eq!(san.len(), 2);
    assert!(matches!(&san[0], GeneralName::DnsName(name) if name == "builder.crown.example"));
    assert!(matches!(&san[1], GeneralName::IpAddress(ip) if ip == &[10, 0, 0, 1]));

    // The generated DER must parse back into an equivalent structure.
    let reparsed = Certificate::parse(&built.encode()).unwrap();
    assert!(reparsed.verify_signature(reparsed.public_key()).unwrap());
    assert_eq!(
        reparsed.subject().common_name().unwrap(),
        "builder.crown.example"
    );
    assert_eq!(reparsed.encode(), built.encode());
    assert_eq!(
        reparsed.public_key().to_algorithm_and_key().unwrap(),
        key.public_key().unwrap().to_algorithm_and_key().unwrap()
    );
}

#[test]
fn signing_algorithms_roundtrip() {
    let mut rng = TestRng(99);
    let message = b"crown x509 signing test";
    let cases: [(PrivateKey, SignatureAlgorithm); 6] = [
        (
            private_key(RSA_PKCS8_PEM),
            SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
        ),
        (
            private_key(RSA_PKCS8_PEM),
            SignatureAlgorithm::RsaPss {
                hash: Hash::Sha256,
                salt_len: 32,
            },
        ),
        (
            private_key(EC_PKCS8_PEM),
            SignatureAlgorithm::Ecdsa(Hash::Sha384),
        ),
        (private_key(ED_PKCS8_PEM), SignatureAlgorithm::Ed25519),
        (private_key(SM2_PKCS8_PEM), SignatureAlgorithm::Sm2),
        (
            private_key(MLDSA_PKCS8_PEM),
            SignatureAlgorithm::MlDsa(crate::ml_dsa::MlDsaVariant::MlDsa65),
        ),
    ];
    let mut checked = 0;
    for (key, algorithm) in cases {
        let signature = key.sign(algorithm, message, &mut rng).unwrap();
        assert!(
            algorithm
                .verify(&key.public_key().unwrap(), message, &signature)
                .unwrap(),
            "{algorithm:?} signature did not verify"
        );
        // A different message must fail.
        let bad = algorithm
            .verify(&key.public_key().unwrap(), b"other", &signature)
            .unwrap();
        assert!(!bad, "{algorithm:?} verified the wrong message");
        checked += 1;
    }
    assert!(checked >= 6, "only {checked} signature algorithms verified");
}

#[test]
fn der_signature_helpers() {
    use crate::bn::Bn;
    let r = Bn::from_be_bytes(&[0x80]);
    let s = Bn::from_be_bytes(&[0x7f]);
    let encoded = crate::x509::algorithm::encode_ecdsa_signature(&r, &s);
    let (r2, s2) = crate::x509::algorithm::decode_ecdsa_signature(&encoded).unwrap();
    assert_eq!(r, r2);
    assert_eq!(s, s2);
    // Known encoding: SEQUENCE { INTEGER 0x0080, INTEGER 0x7f }.
    assert_eq!(
        encoded,
        alloc::vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x7f]
    );
}

#[test]
fn algorithm_identifier_mapping() {
    for algorithm in [
        SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
        SignatureAlgorithm::RsaPss {
            hash: Hash::Sha384,
            salt_len: 48,
        },
        SignatureAlgorithm::Ecdsa(Hash::Sha512),
        SignatureAlgorithm::Ed25519,
        SignatureAlgorithm::Ed448,
        SignatureAlgorithm::Sm2,
        SignatureAlgorithm::Dsa(Hash::Sha256),
        SignatureAlgorithm::MlDsa(crate::ml_dsa::MlDsaVariant::MlDsa44),
        SignatureAlgorithm::SlhDsa(crate::slh_dsa::SlhDsaVariant::Sha2_128f),
    ] {
        let identifier = algorithm.to_identifier();
        let parsed = SignatureAlgorithm::from_identifier(&identifier).unwrap();
        assert_eq!(algorithm, parsed, "roundtrip failed for {algorithm:?}");
        // And the identifier survives DER encoding.
        let encoded = identifier.encode();
        let mut reader = Reader::new(&encoded);
        let reparsed = crate::x509::algorithm::AlgorithmIdentifier::parse(&mut reader).unwrap();
        assert_eq!(identifier, reparsed);
    }
}

#[test]
fn name_parsing_and_rendering() {
    let ca = cert(CA_PEM);
    let name = ca.subject();
    assert_eq!(
        name.get(oid::OID_AT_COMMON_NAME).unwrap().text().unwrap(),
        "Crown Test Root CA"
    );
    assert_eq!(name.get_all(oid::OID_AT_ORGANIZATION).len(), 1);
    assert_eq!(name.organization().unwrap(), "Crown Test");
    // Roundtrip.
    let encoded = name.encode();
    let mut reader = Reader::new(&encoded);
    let reparsed = Name::parse(&mut reader).unwrap();
    assert_eq!(&reparsed, name);
    assert_eq!(reparsed.to_string(), name.to_string());
}

#[test]
fn extension_value_parsing_errors_are_reported() {
    // A basicConstraints value that is not a SEQUENCE must error.
    let extension = crate::x509::extensions::Extension::new(
        crate::asn1::oid::ObjectIdentifier::new(oid::OID_BASIC_CONSTRAINTS).unwrap(),
        true,
        alloc::vec![0x02, 0x01, 0x00],
    );
    assert!(extension.parsed().is_err());
}

#[test]
fn validity_window_helpers() {
    let not_before = Asn1Time::parse_utc(b"230101000000Z").unwrap();
    let not_after = Asn1Time::parse_utc(b"280101000000Z").unwrap();
    let validity = crate::x509::cert::Validity {
        not_before,
        not_after,
    };
    let inside = Asn1Time::parse_utc(b"250101000000Z").unwrap().to_unix();
    assert!(validity.contains(inside));
    assert!(!validity.contains(not_before.to_unix() - 1));
}

#[test]
fn certificate_policies_parse_losslessly() {
    use crate::x509::extensions::{CertificatePolicies, ParsedExtension, PolicyQualifier};

    let certificate = cert(POLICIES_PEM);
    let extension = certificate
        .tbs()
        .extension(oid::OID_CERTIFICATE_POLICIES)
        .expect("certificatePolicies present");
    let ParsedExtension::CertificatePolicies(policies) = extension.parsed().unwrap() else {
        panic!("not certificatePolicies");
    };

    assert_eq!(policies.policies.len(), 2);
    assert_eq!(
        policies.policy_identifiers()[0].to_string(),
        "2.23.140.1.2.1"
    );
    let first = &policies.policies[0];
    assert_eq!(first.qualifiers.len(), 2);
    match &first.qualifiers[0] {
        PolicyQualifier::CpsUri(uri) => assert_eq!(uri, "http://cps.crown.example"),
        other => panic!("expected CPS URI, got {other:?}"),
    }
    match &first.qualifiers[1] {
        PolicyQualifier::UserNotice(notice) => {
            let text = notice.explicit_text.as_ref().expect("explicitText");
            assert_eq!(text.text().unwrap(), "crown test notice");
            // OpenSSL encodes DisplayText as VisibleString; the tag survives.
            assert_eq!(text.tag, crate::asn1::der::VISIBLE_STRING);
            let reference = notice.notice_ref.as_ref().expect("noticeRef");
            assert_eq!(reference.organization.text().unwrap(), "Crown Fixture");
            assert_eq!(reference.notice_numbers, vec![1, 2, 3]);
        }
        other => panic!("expected userNotice, got {other:?}"),
    }
    assert!(policies.policies[1].qualifiers.is_empty());
    assert_eq!(
        policies.policies[1].policy_identifier.to_string(),
        "1.2.3.4.5"
    );
    assert!(policies.contains(&[2, 23, 140, 1, 2, 1]));
    assert!(!policies.contains(&[1, 2, 3]));

    // The structured form re-encodes byte-exactly.
    assert_eq!(policies.encode(), extension.value);
    let reparsed = CertificatePolicies::parse(&extension.value).unwrap();
    assert_eq!(reparsed, policies);

    // An unknown qualifier survives a roundtrip as raw DER.
    let qualifier = PolicyQualifier::Other {
        oid: crate::asn1::oid::ObjectIdentifier::new(&[1, 2, 3, 4]).unwrap(),
        value: crate::asn1::der::octet_string(b"opaque"),
    };
    let encoded = qualifier.encode();
    assert_eq!(
        PolicyQualifier::parse(&mut Reader::new(&encoded)).unwrap(),
        qualifier
    );
}

#[test]
fn crl_distribution_points_parse_losslessly() {
    use crate::x509::extensions::{
        AuthorityInfoAccess, CrlDistributionPoints, GeneralName, ParsedExtension,
    };

    let certificate = cert(CRLDP_PEM);
    let extension = certificate
        .tbs()
        .extension(oid::OID_CRL_DISTRIBUTION_POINTS)
        .expect("crlDistributionPoints present");
    let ParsedExtension::CrlDistributionPoints(points) = extension.parsed().unwrap() else {
        panic!("not crlDistributionPoints");
    };

    assert_eq!(points.points.len(), 1);
    let point = &points.points[0];
    let name = point.distribution_point.as_ref().expect("fullName");
    assert_eq!(
        name.full_name.as_deref(),
        Some(
            &[GeneralName::Uri(String::from(
                "http://crl.crown.example/root.crl"
            ))][..]
        )
    );
    assert!(name.relative_name.is_none());
    // Key compromise (bit 1) and cessation of operation (bit 5).
    assert_eq!(point.reasons, Some(0x22));
    assert!(point.has_reason(1) && point.has_reason(5));
    assert!(!point.has_reason(2));
    assert_eq!(
        point.crl_issuer,
        vec![GeneralName::Uri(String::from("http://ca.crown.example"))]
    );
    assert_eq!(points.uris(), vec!["http://crl.crown.example/root.crl"]);

    // Byte-exact re-encode.
    assert_eq!(points.encode(), extension.value);
    assert_eq!(
        CrlDistributionPoints::parse(&extension.value).unwrap(),
        points
    );

    // The authorityInfoAccess next to it keeps every AccessDescription.
    let access = certificate
        .tbs()
        .extension(oid::OID_AUTHORITY_INFO_ACCESS)
        .expect("authorityInfoAccess present");
    let ParsedExtension::AuthorityInfoAccess(access) = access.parsed().unwrap() else {
        panic!("not authorityInfoAccess");
    };
    assert_eq!(access.descriptions.len(), 2);
    assert!(access.descriptions[0].method.matches(oid::OID_AD_OCSP));
    assert!(access.descriptions[1]
        .method
        .matches(oid::OID_AD_CA_ISSUERS));
    assert_eq!(access.ocsp_uris(), vec!["http://ocsp.crown.example"]);
    assert_eq!(
        access.ca_issuers_uris(),
        vec!["http://certs.crown.example/ca.crt"]
    );
    assert_eq!(access.encode(), access_extension_value(&certificate));
    assert_eq!(
        AuthorityInfoAccess::parse(&access_extension_value(&certificate)).unwrap(),
        access
    );
}

/// The raw value of a certificate's `authorityInfoAccess` extension.
fn access_extension_value(certificate: &Certificate) -> Vec<u8> {
    certificate
        .tbs()
        .extension(oid::OID_AUTHORITY_INFO_ACCESS)
        .expect("authorityInfoAccess present")
        .value
        .clone()
}

#[test]
fn subject_directory_attributes_roundtrip() {
    use crate::x509::extensions::{ParsedExtension, SubjectDirectoryAttributes};

    let attributes = SubjectDirectoryAttributes {
        attributes: alloc::vec![alloc::vec![crate::x509::attribute::Attribute::new(
            crate::asn1::oid::ObjectIdentifier::new(&[2, 5, 4, 3]).unwrap(),
            alloc::vec![crate::asn1::der::utf8_string("Dir Attribute")],
        )]],
    };
    let extension = crate::x509::extensions::Extension::new(
        crate::asn1::oid::ObjectIdentifier::new(oid::OID_SUBJECT_DIRECTORY_ATTRIBUTES).unwrap(),
        false,
        attributes.encode(),
    );
    let ParsedExtension::SubjectDirectoryAttributes(parsed) = extension.parsed().unwrap() else {
        panic!("not subjectDirectoryAttributes");
    };
    assert_eq!(parsed, attributes);
    assert_eq!(
        parsed.attributes[0][0].first_text().as_deref(),
        Some("Dir Attribute")
    );
    assert_eq!(parsed.encode(), attributes.encode());
}
