//! RFC 5280 path-validation gate.
//!
//! The fixtures under `tests/data/pki/verify/` were generated with the
//! vendored OpenSSL 3.5.8 CLI (see the task log): a two-level PKI with name
//! constraints, a path-length-limited sub-CA, a policy chain with
//! `requireExplicitPolicy`, an intermediate-signed CRL that revokes one leaf,
//! and leaf variants for every negative case. OpenSSL verifies the same
//! expectations (`openssl verify`), so both implementations are pinned to the
//! same input.

use crown::asn1::oid::ObjectIdentifier;
use crown::x509::cert::Certificate;
use crown::x509::crl::CertificateList;
use crown::x509::extensions::{
    AccessDescription, CrlReason, Extension, GeneralName, GeneralSubtree, InhibitAnyPolicy,
    InvalidityDate, IssuingDistributionPoint, NameConstraints, ParsedExtension, PolicyConstraints,
    PolicyMapping, PolicyMappings, SubjectInfoAccess, TlsFeature,
};
use crown::x509::verify::{
    verify_certificate, Purpose, Store, VerifyError, VerifyFlags, VerifyOptions,
};
use crown::x509::{Hash, Name};

const BASE: &str = "tests/data/pki/verify/";

fn read(path: &str) -> Vec<u8> {
    std::fs::read(format!("{BASE}{path}")).unwrap_or_else(|err| panic!("read {path}: {err}"))
}

fn read_text(path: &str) -> String {
    String::from_utf8(read(path)).unwrap_or_else(|err| panic!("utf8 {path}: {err}"))
}

fn cert(name: &str) -> Certificate {
    Certificate::from_pem(&read_text(&format!("{name}.pem")))
        .unwrap_or_else(|err| panic!("certificate {name}: {err}"))
}

fn crl(name: &str) -> CertificateList {
    CertificateList::from_pem(&read_text(&format!("{name}.crl")))
        .unwrap_or_else(|err| panic!("crl {name}: {err}"))
}

/// A verification time inside every fixture's validity window.
fn verify_time() -> i64 {
    cert("leaf_good").validity().not_before.to_unix() + 3600
}

fn root_store() -> Store {
    let mut store = Store::new();
    store.add_trusted_certificate(cert("root"));
    store
}

fn options(untrusted: Vec<Certificate>) -> VerifyOptions {
    VerifyOptions {
        time: Some(verify_time()),
        untrusted,
        ..Default::default()
    }
}

#[test]
fn chain_verifies_and_reports_anchors() {
    let store = root_store();
    let leaf = cert("leaf_good");
    let intermediate = cert("inter");
    let result = verify_certificate(&store, &leaf, &options(vec![intermediate.clone()]))
        .expect("chain verifies");
    assert_eq!(result.chain.len(), 3);
    assert_eq!(result.leaf().subject(), leaf.subject());
    assert_eq!(
        result.trust_anchor().tbs_der(),
        store.trusted_certificates()[0].tbs_der()
    );
    assert_eq!(result.chain[1].subject(), intermediate.subject());

    // The chain is rebuilt from the caller's intermediates only.
    let missing = verify_certificate(&store, &leaf, &options(Vec::new()));
    assert_eq!(
        missing.unwrap_err(),
        VerifyError::UnableToGetIssuerCertificate
    );

    let in_chain = verify_certificate(&store, &leaf, &options(vec![intermediate, cert("root")]));
    assert!(
        in_chain.is_ok(),
        "root in untrusted still reaches the anchor"
    );

    let no_time = VerifyOptions {
        time: Some(0),
        ..options(vec![cert("inter")])
    };
    assert_eq!(
        verify_certificate(&store, &leaf, &no_time).unwrap_err(),
        VerifyError::CertificateNotYetValid
    );
}

#[test]
fn self_signed_leaf_is_rejected() {
    let store = Store::new();
    let err = verify_certificate(&store, &cert("root"), &options(Vec::new())).unwrap_err();
    assert_eq!(err, VerifyError::DepthZeroSelfSignedCertificate);
    assert_eq!(err.code(), 18);
}

#[test]
fn name_constraints_are_enforced() {
    let store = root_store();
    let intermediate = cert("inter");
    let good = verify_certificate(
        &store,
        &cert("leaf_good"),
        &options(vec![intermediate.clone()]),
    );
    assert!(good.is_ok(), "www.example.com is permitted");

    let bad_dns = verify_certificate(
        &store,
        &cert("leaf_bad_dns"),
        &options(vec![intermediate.clone()]),
    )
    .unwrap_err();
    assert_eq!(bad_dns, VerifyError::PermittedViolation);
    assert_eq!(bad_dns.code(), 47);

    let bad_email = verify_certificate(
        &store,
        &cert("leaf_bad_email"),
        &options(vec![intermediate.clone()]),
    )
    .unwrap_err();
    assert_eq!(bad_email, VerifyError::PermittedViolation);

    let excluded = verify_certificate(&store, &cert("leaf_excluded"), &options(vec![intermediate]))
        .unwrap_err();
    assert_eq!(excluded, VerifyError::ExcludedViolation);
    assert_eq!(excluded.code(), 48);
}

#[test]
fn path_length_is_enforced() {
    let store = root_store();
    let untrusted = vec![cert("inter"), cert("sub")];
    let err = verify_certificate(&store, &cert("sub_leaf"), &options(untrusted)).unwrap_err();
    assert_eq!(err, VerifyError::PathLengthExceeded);
    assert_eq!(err.code(), 25);
}

#[test]
fn purposes_are_checked() {
    let store = root_store();
    let intermediate = cert("inter");
    let server = options(vec![intermediate.clone()]).purpose(Purpose::SslServer);
    assert!(verify_certificate(&store, &cert("leaf_good"), &server).is_ok());

    let server_on_client = options(vec![intermediate.clone()]).purpose(Purpose::SslServer);
    let err = verify_certificate(&store, &cert("leaf_client"), &server_on_client).unwrap_err();
    assert_eq!(err, VerifyError::InvalidPurpose);
    assert_eq!(err.code(), 26);

    let client = options(vec![intermediate]).purpose(Purpose::SslClient);
    assert!(verify_certificate(&store, &cert("leaf_client"), &client).is_ok());
}

#[test]
fn crl_revocation_is_enforced() {
    let mut store = root_store();
    store.add_crl(crl("inter"));
    let intermediate = cert("inter");
    let flags = VerifyFlags {
        crl_check: true,
        ..Default::default()
    };
    let checking = options(vec![intermediate.clone()]).flags(flags);

    assert!(verify_certificate(&store, &cert("leaf_good"), &checking).is_ok());

    let revoked = verify_certificate(&store, &cert("leaf_revoked"), &checking).unwrap_err();
    assert_eq!(revoked, VerifyError::CertificateRevoked);
    assert_eq!(revoked.code(), 23);

    // Without CRL checking the same chain verifies.
    assert!(
        verify_certificate(&store, &cert("leaf_revoked"), &options(vec![intermediate])).is_ok()
    );

    // A chain with checking but no CRL in the store fails to find one.
    let empty_store = root_store();
    let err = verify_certificate(&empty_store, &cert("leaf_good"), &checking).unwrap_err();
    assert_eq!(err, VerifyError::UnableToGetCrl);
}

#[test]
fn policies_are_processed() {
    let mut store = Store::new();
    store.add_trusted_certificate(cert("policy_root"));
    let flags = VerifyFlags {
        policy_check: true,
        ..Default::default()
    };
    let checking = options(vec![cert("policy_inter")]).flags(flags);

    assert!(verify_certificate(&store, &cert("policy_leaf_good"), &checking).is_ok());

    let err = verify_certificate(&store, &cert("policy_leaf_none"), &checking).unwrap_err();
    assert_eq!(err, VerifyError::NoExplicitPolicy);
    assert_eq!(err.code(), 43);
}

#[test]
fn fixture_extensions_parse_as_typed_values() {
    let intermediate = cert("inter");
    let extension = intermediate
        .tbs()
        .extension(crown::asn1::oid::OID_NAME_CONSTRAINTS)
        .expect("name constraints");
    match extension.parsed().expect("parse") {
        ParsedExtension::NameConstraints(constraints) => {
            let permitted = constraints.permitted.expect("permitted");
            assert!(permitted.iter().any(|subtree| matches!(
                &subtree.base,
                GeneralName::DnsName(name) if name == "example.com"
            )));
            let excluded = constraints.excluded.expect("excluded");
            assert!(excluded
                .iter()
                .any(|subtree| matches!(&subtree.base, GeneralName::DnsName(name) if name == "evil.example.com")));
        }
        other => panic!("unexpected extension: {other:?}"),
    }

    let crl = crl("inter");
    let number = crl
        .tbs()
        .extensions
        .iter()
        .find(|extension| extension.oid.matches(crown::asn1::oid::OID_CRL_NUMBER))
        .expect("CRL number");
    assert!(matches!(
        number.parsed().expect("parse"),
        ParsedExtension::CrlNumber(_)
    ));
    let entry = crl
        .tbs()
        .revoked_certificates
        .first()
        .expect("one revoked entry");
    let reason = entry
        .extensions
        .iter()
        .find(|extension| extension.oid.matches(crown::asn1::oid::OID_REASON_CODE))
        .expect("reason code");
    assert!(matches!(
        reason.parsed().expect("parse"),
        ParsedExtension::CrlReason(CrlReason::KeyCompromise)
    ));

    let policy_inter = cert("policy_inter");
    assert!(policy_inter
        .tbs()
        .extensions
        .iter()
        .any(|extension| matches!(
            extension.parsed(),
            Ok(ParsedExtension::CertificatePolicies(_))
        )));
    assert!(policy_inter
        .tbs()
        .extensions
        .iter()
        .any(|extension| matches!(
            extension.parsed(),
            Ok(ParsedExtension::PolicyConstraints(_))
        )));
}

#[test]
fn extension_round_trips() {
    // nameConstraints
    let constraints = NameConstraints {
        permitted: Some(vec![GeneralSubtree {
            base: GeneralName::DnsName("example.com".to_string()),
            minimum: 0,
            maximum: None,
        }]),
        excluded: Some(vec![GeneralSubtree {
            base: GeneralName::IpAddress(vec![10, 0, 0, 0, 255, 0, 0, 0]),
            minimum: 0,
            maximum: None,
        }]),
    };
    let encoded = constraints.encode();
    assert_eq!(NameConstraints::parse(&encoded).unwrap(), constraints);
    assert!(constraints.permits(&GeneralName::DnsName("www.example.com".to_string())));
    assert!(!constraints.permits(&GeneralName::DnsName("www.other.test".to_string())));
    assert!(!constraints.permits(&GeneralName::IpAddress(vec![10, 1, 2, 3])));

    // policyConstraints / inhibitAnyPolicy / policyMappings
    let policy_constraints = PolicyConstraints {
        require_explicit_policy: Some(0),
        inhibit_policy_mapping: Some(2),
    };
    assert_eq!(
        PolicyConstraints::parse(&policy_constraints.encode()).unwrap(),
        policy_constraints
    );
    assert_eq!(
        InhibitAnyPolicy::parse(&InhibitAnyPolicy { skip_certs: 3 }.encode()).unwrap(),
        InhibitAnyPolicy { skip_certs: 3 }
    );
    let mappings = PolicyMappings {
        mappings: vec![PolicyMapping {
            issuer_domain_policy: ObjectIdentifier::new(&[1, 3, 6, 1, 4, 1, 99999, 1]).unwrap(),
            subject_domain_policy: ObjectIdentifier::new(&[1, 3, 6, 1, 4, 1, 99999, 2]).unwrap(),
        }],
    };
    assert_eq!(PolicyMappings::parse(&mappings.encode()).unwrap(), mappings);

    // subjectInfoAccess / tlsFeature / IDP round trip through Extension.
    let sia = SubjectInfoAccess {
        descriptions: vec![AccessDescription {
            method: ObjectIdentifier::new(&[1, 3, 6, 1, 5, 5, 7, 48, 5]).unwrap(),
            location: GeneralName::Uri("https://repo.example.com".to_string()),
        }],
    };
    assert_eq!(SubjectInfoAccess::parse(&sia.encode()).unwrap(), sia);
    let tls = TlsFeature {
        features: vec![5, 17],
    };
    assert_eq!(TlsFeature::parse(&tls.encode()).unwrap(), tls);

    let idp = IssuingDistributionPoint {
        distribution_point: None,
        only_contains_user_certs: true,
        only_contains_ca_certs: false,
        only_some_reasons: Some(1 << 1),
        indirect_crl: false,
        only_contains_attribute_certs: false,
    };
    assert_eq!(IssuingDistributionPoint::parse(&idp.encode()).unwrap(), idp);
    assert!(idp.has_reason(1));
    assert!(!idp.has_reason(2));

    // CRL entry helpers.
    assert_eq!(
        CrlReason::parse(&CrlReason::KeyCompromise.encode()).unwrap(),
        CrlReason::KeyCompromise
    );
    let date = cert("leaf_good").validity().not_before;
    assert_eq!(
        InvalidityDate::parse(&InvalidityDate { date }.encode())
            .unwrap()
            .date
            .to_unix(),
        date.to_unix()
    );

    // Fingerprint sanity for the hash used in AKI fallbacks.
    assert_eq!(Hash::Sha1.output_len(), 20);
    let _ = Extension::new(
        ObjectIdentifier::new(&[2, 5, 29, 30]).unwrap(),
        true,
        constraints.encode(),
    );
}

/// A deterministic RNG for the in-memory issuance test.
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

#[test]
fn issuance_and_crl_round_trip() {
    use crown::ec::CurveId;
    use crown::x509::extensions::{
        authority_key_identifier, basic_constraints, crl_number, key_usage, subject_key_identifier,
    };
    use crown::x509::{
        CertificateBuilder, CertificationRequest, KeyUsage, PrivateKey, RevokedCertificate,
        SignatureAlgorithm, SubjectPublicKeyInfo,
    };

    let mut rng = TestRng(0x5eed);
    let algorithm = SignatureAlgorithm::Ecdsa(Hash::Sha256);
    let leaf_fixture = cert("leaf_good");
    let validity = leaf_fixture.validity();
    let (not_before, not_after) = (validity.not_before, validity.not_after);

    let ec_key = |rng: &mut TestRng| -> PrivateKey {
        let (scalar, _) = crown::ecdh::generate(CurveId::P256, rng).expect("ec keygen");
        PrivateKey::Ec {
            curve: CurveId::P256,
            scalar,
        }
    };
    let ca_usage = || KeyUsage {
        key_cert_sign: true,
        crl_sign: true,
        ..Default::default()
    };

    // Root signs itself; its key id anchors the chain.
    let root_key = ec_key(&mut rng);
    let root_key_id = SubjectPublicKeyInfo::from_public_key(&root_key.public_key().unwrap())
        .unwrap()
        .key_identifier()
        .unwrap();
    let root = Certificate::self_signed(
        Name::from_common_name("Issued Root"),
        algorithm,
        &root_key,
        not_before,
        not_after,
        vec![
            basic_constraints(true, Some(1)),
            key_usage(ca_usage()),
            subject_key_identifier(&root_key_id),
            authority_key_identifier(&root_key_id),
        ],
        &mut rng,
    )
    .expect("self-signed root");

    // An intermediate issued from a CSR, carrying name constraints.
    let intermediate_key = ec_key(&mut rng);
    let intermediate_spki =
        SubjectPublicKeyInfo::from_public_key(&intermediate_key.public_key().unwrap()).unwrap();
    let request = CertificationRequest::build(
        Name::from_common_name("Issued Intermediate"),
        intermediate_spki,
        Vec::new(),
        algorithm,
        &intermediate_key,
        &mut rng,
    )
    .expect("csr");
    assert!(request.verify_signature().unwrap(), "proof of possession");
    let intermediate_key_id = request
        .info()
        .subject_public_key_info
        .key_identifier()
        .unwrap();
    let constraints = NameConstraints {
        permitted: Some(vec![GeneralSubtree {
            base: GeneralName::DnsName("issued.example.com".to_string()),
            minimum: 0,
            maximum: None,
        }]),
        excluded: None,
    };
    let intermediate = CertificateBuilder::from_request(&request, algorithm)
        .issuer(root.subject().clone())
        .serial(vec![2])
        .validity(not_before, not_after)
        .extension(basic_constraints(true, Some(0)))
        .extension(key_usage(ca_usage()))
        .extension(subject_key_identifier(&intermediate_key_id))
        .extension(authority_key_identifier(&root_key_id))
        .extension(Extension::new(
            ObjectIdentifier::new(&[2, 5, 29, 30]).unwrap(),
            true,
            constraints.encode(),
        ))
        .sign(&root_key, &mut rng)
        .expect("intermediate");

    // A leaf issued from another CSR.
    let leaf_key = ec_key(&mut rng);
    let leaf_spki = SubjectPublicKeyInfo::from_public_key(&leaf_key.public_key().unwrap()).unwrap();
    let leaf_request = CertificationRequest::build(
        Name::from_common_name("www.issued.example.com"),
        leaf_spki,
        Vec::new(),
        algorithm,
        &leaf_key,
        &mut rng,
    )
    .expect("leaf csr");
    let leaf = CertificateBuilder::from_request(&leaf_request, algorithm)
        .issuer(intermediate.subject().clone())
        .serial(vec![3])
        .validity(not_before, not_after)
        .extension(basic_constraints(false, None))
        .extension(crown::x509::extensions::subject_alt_name(
            &["www.issued.example.com".to_string()],
            &[],
        ))
        .extension(crown::x509::extensions::extended_key_usage(&[
            crown::asn1::oid::OID_KP_SERVER_AUTH,
        ]))
        .extension(authority_key_identifier(&intermediate_key_id))
        .sign(&intermediate_key, &mut rng)
        .expect("leaf");

    // The issued chain validates.
    let mut store = Store::new();
    store.add_trusted_certificate(root.clone());
    let opts = options(vec![intermediate.clone()]).purpose(Purpose::SslServer);
    let result = verify_certificate(&store, &leaf, &opts).expect("issued chain verifies");
    assert_eq!(result.chain.len(), 3);

    // A leaf outside the permitted subtree is rejected.
    let mut bad_builder = CertificateBuilder::from_request(&leaf_request, algorithm);
    bad_builder.subject = Name::from_common_name("www.other.test");
    let bad = bad_builder
        .issuer(intermediate.subject().clone())
        .serial(vec![4])
        .validity(not_before, not_after)
        .extension(basic_constraints(false, None))
        .extension(crown::x509::extensions::subject_alt_name(
            &["www.other.test".to_string()],
            &[],
        ))
        .sign(&intermediate_key, &mut rng)
        .expect("bad leaf");
    let err = verify_certificate(&store, &bad, &options(vec![intermediate.clone()])).unwrap_err();
    assert_eq!(err, VerifyError::PermittedViolation);
    let _ = bad;

    // Revoke the leaf with a crown-built CRL and check it.
    let entry = RevokedCertificate::new(leaf.serial_number().to_vec(), not_before)
        .reason(CrlReason::KeyCompromise);
    assert!(entry.extensions.iter().any(|extension| matches!(
        extension.parsed(),
        Ok(ParsedExtension::CrlReason(CrlReason::KeyCompromise))
    )));
    let crl = CertificateList::build(
        intermediate.subject().clone(),
        not_before,
        Some(not_after),
        vec![entry],
        vec![crl_number(&[1])],
        algorithm,
        &intermediate_key,
        &mut rng,
    )
    .expect("crl");
    // The built CRL round-trips (extensions are re-encoded with tag [0]).
    let reparsed = CertificateList::parse(&crl.encode()).expect("crl round trip");
    assert_eq!(reparsed.tbs().revoked_certificates.len(), 1);
    assert!(reparsed
        .tbs()
        .extensions
        .iter()
        .any(|extension| extension.oid.matches(crown::asn1::oid::OID_CRL_NUMBER)));
    let flags = VerifyFlags {
        crl_check: true,
        ..Default::default()
    };
    let checking = options(vec![intermediate]).flags(flags);
    let mut revoking_store = store.clone();
    revoking_store.add_crl(crl);
    let err = verify_certificate(&revoking_store, &leaf, &checking).unwrap_err();
    assert_eq!(err, VerifyError::CertificateRevoked);
}
