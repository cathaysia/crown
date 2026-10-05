//! Integration tests for the OCSP (RFC 6960) module.
//!
//! The `ocsp_*` fixtures were generated with the vendored OpenSSL 3.5.8 CLI
//! (see `src/ocsp/tests.rs` for the exact commands); `ec.pem` /
//! `ec_pkcs8.pem` act as the issuer. Every family asserts a minimum number of
//! checked items so a broken harness cannot silently degrade into skipping
//! everything, and a final optional test drives the OpenSSL CLI against
//! crown-built artifacts when the vendored binary is available.

use std::ffi::OsStr;
use std::path::PathBuf;

use crown::asn1::pem;
use crown::asn1::time::Asn1Time;
use crown::ocsp::{
    CertId, CertStatus, CrlReason, OcspRequest, OcspResponder, OcspResponse, OcspResponseStatus,
    ResponderId, SingleResponse,
};
use crown::x509::algorithm::{Hash, SignatureAlgorithm};
use crown::x509::cert::Certificate;
use crown::x509::keys::{PrivateKey, PrivateKeyInfo};

const REQUEST: &[u8] = include_bytes!("data/pki/ocsp_request.der");
const REQUEST_REVOKED: &[u8] = include_bytes!("data/pki/ocsp_request_revoked.der");
const REQUEST_SHA256: &[u8] = include_bytes!("data/pki/ocsp_request_sha256.der");
const RESPONSE_GOOD: &[u8] = include_bytes!("data/pki/ocsp_response_good.der");
const RESPONSE_REVOKED: &[u8] = include_bytes!("data/pki/ocsp_response_revoked.der");
const RESPONSE_DELEGATED: &[u8] = include_bytes!("data/pki/ocsp_response_delegated.der");
const RESPONSE_BYKEY: &[u8] = include_bytes!("data/pki/ocsp_response_bykey.der");

const CA_PEM: &str = include_str!("data/pki/ec.pem");
const CA_KEY_PEM: &str = include_str!("data/pki/ec_pkcs8.pem");
const LEAF_PEM: &str = include_str!("data/pki/ocsp_leaf.pem");
const REVOKED_PEM: &str = include_str!("data/pki/ocsp_revoked.pem");
const RESPONDER_PEM: &str = include_str!("data/pki/ocsp_responder.pem");
const RESPONDER_KEY_PEM: &str = include_str!("data/pki/rsa_pkcs8.pem");

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

fn certificate(pem_text: &str) -> Certificate {
    Certificate::from_pem(pem_text).expect("certificate PEM")
}

fn private_key(pem_text: &str) -> PrivateKey {
    let block = pem::parse_first(pem_text).expect("PEM block");
    PrivateKeyInfo::parse(&block.data)
        .expect("PKCS#8")
        .decode()
        .expect("private key")
}

fn produced_at() -> Asn1Time {
    Asn1Time::parse_generalized(b"20261005150000Z").expect("static time")
}

#[test]
fn openssl_requests_parse_and_match_certificates() {
    let ca = certificate(CA_PEM);
    let leaf = certificate(LEAF_PEM);
    let revoked = certificate(REVOKED_PEM);
    let mut checked = 0;

    for (der, hash, nonce_len) in [
        (REQUEST, Hash::Sha1, 16),
        (REQUEST_REVOKED, Hash::Sha1, 16),
        (REQUEST_SHA256, Hash::Sha256, 16),
    ] {
        let request = OcspRequest::parse(der).unwrap_or_else(|err| panic!("parse: {err}"));
        assert_eq!(request.encode(), der, "re-encode");
        assert!(request.version.is_none());
        assert_eq!(request.cert_id().unwrap().hash().unwrap(), hash);
        assert_eq!(request.nonce().unwrap().unwrap().len(), nonce_len);
        checked += 1;
    }
    assert!(checked >= 3, "only {checked} requests checked");

    assert!(OcspRequest::parse(REQUEST)
        .unwrap()
        .cert_id()
        .unwrap()
        .matches(&leaf, &ca)
        .unwrap());
    assert!(OcspRequest::parse(REQUEST_REVOKED)
        .unwrap()
        .cert_id()
        .unwrap()
        .matches(&revoked, &ca)
        .unwrap());
}

#[test]
fn openssl_responses_parse_verify_and_match() {
    let ca = certificate(CA_PEM);
    let leaf = certificate(LEAF_PEM);
    let revoked = certificate(REVOKED_PEM);
    let responder = certificate(RESPONDER_PEM);
    let mut checked = 0;

    // Good response, signed by the issuer itself.
    let good = OcspResponse::parse(RESPONSE_GOOD).unwrap();
    assert_eq!(good.status, OcspResponseStatus::Successful);
    assert_eq!(good.encode(), RESPONSE_GOOD, "re-encode");
    let basic = good.basic().unwrap();
    assert_eq!(
        basic.tbs_response_data.responder_id,
        ResponderId::ByName(ca.subject().clone())
    );
    let single = &basic.tbs_response_data.responses[0];
    assert_eq!(single.cert_status, CertStatus::Good);
    assert!(single.matches(&leaf, &ca).unwrap());
    assert!(!single.matches(&revoked, &ca).unwrap());
    assert!(single.next_update.is_some());
    good.verify(&ca).unwrap();
    good.check_request_nonce(&OcspRequest::parse(REQUEST).unwrap())
        .unwrap();
    checked += 1;

    // Revoked response with the reason from the OpenSSL index file.
    let revoked_response = OcspResponse::parse(RESPONSE_REVOKED).unwrap();
    let basic = revoked_response.basic().unwrap();
    assert!(basic.tbs_response_data.responses[0]
        .matches(&revoked, &ca)
        .unwrap());
    assert_eq!(
        basic.tbs_response_data.responses[0].cert_status,
        CertStatus::Revoked {
            revocation_time: Asn1Time::parse_generalized(b"20261005143800Z").unwrap(),
            revocation_reason: Some(CrlReason::KeyCompromise),
        }
    );
    revoked_response.verify(&ca).unwrap();
    checked += 1;

    // Delegated responder (embedded certificate with OCSP signing EKU).
    let delegated = OcspResponse::parse(RESPONSE_DELEGATED).unwrap();
    delegated.verify(&ca).unwrap();
    delegated
        .verify_with_responder(&ca, Some(&responder))
        .unwrap();
    checked += 1;

    // byKey responder id (SHA-1 of the issuer's public key).
    let by_key = OcspResponse::parse(RESPONSE_BYKEY).unwrap();
    assert_eq!(
        by_key.basic().unwrap().tbs_response_data.responder_id,
        ResponderId::ByKey(
            Hash::Sha1
                .digest(&ca.subject_public_key_info().key)
                .unwrap()
        )
    );
    by_key.verify(&ca).unwrap();
    checked += 1;

    assert!(checked >= 4, "only {checked} responses checked");
}

#[test]
fn crown_builds_and_roundtrips_requests_and_responses() {
    let ca = certificate(CA_PEM);
    let leaf = certificate(LEAF_PEM);
    let responder_cert = certificate(RESPONDER_PEM);
    let mut rng = TestRng(99);
    let mut checked = 0;

    // Request: build, set a nonce, and round-trip DER and PEM.
    let mut request = OcspRequest::request_for(&leaf, &ca, Hash::Sha1).unwrap();
    request.set_nonce(b"0123456789abcdef");
    let der = request.encode();
    let parsed = OcspRequest::parse(&der).unwrap();
    assert_eq!(parsed.encode(), der);
    assert_eq!(
        parsed.nonce().unwrap().as_deref(),
        Some(&b"0123456789abcdef"[..])
    );
    let text = parsed.to_pem();
    assert!(text.starts_with("-----BEGIN OCSP REQUEST-----"));
    assert_eq!(OcspRequest::from_pem(&text).unwrap().encode(), der);
    assert!(parsed.cert_id().unwrap().matches(&leaf, &ca).unwrap());
    checked += 1;

    // Issuer-signed response.
    let cert_id = CertId::for_certificate(&leaf, &ca, Hash::Sha256).unwrap();
    let single = SingleResponse::new(cert_id, CertStatus::Good, produced_at());
    let responder = OcspResponder::for_certificate(
        &ca,
        private_key(CA_KEY_PEM),
        SignatureAlgorithm::Ecdsa(Hash::Sha256),
        false,
    )
    .unwrap();
    let basic = responder
        .respond(
            vec![single],
            produced_at(),
            Some(Asn1Time::parse_generalized(b"20261012150000Z").unwrap()),
            Some(b"0123456789abcdef"),
            &mut rng,
        )
        .unwrap();
    basic.verify(&ca).unwrap();
    let response = OcspResponse::successful(&basic);
    let der = response.encode();
    let parsed = OcspResponse::parse(&der).unwrap();
    parsed.verify(&ca).unwrap();
    assert_eq!(parsed.encode(), der);
    parsed.check_request_nonce(&request).unwrap();
    assert_eq!(parsed.basic().unwrap().tbs_response_data.responses.len(), 1);
    let text = response.to_pem();
    assert!(text.starts_with("-----BEGIN OCSP RESPONSE-----"));
    assert_eq!(OcspResponse::from_pem(&text).unwrap().encode(), der);
    checked += 1;

    // Delegated responder, byKey responder id, RSA PKCS#1 v1.5 signature.
    let delegated = OcspResponder::for_certificate(
        &responder_cert,
        private_key(RESPONDER_KEY_PEM),
        SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
        true,
    )
    .unwrap();
    assert!(matches!(delegated.responder_id, ResponderId::ByKey(_)));
    let basic = delegated
        .respond(
            vec![SingleResponse::new(
                CertId::for_certificate(&leaf, &ca, Hash::Sha1).unwrap(),
                CertStatus::Revoked {
                    revocation_time: produced_at(),
                    revocation_reason: Some(CrlReason::Superseded),
                },
                produced_at(),
            )],
            produced_at(),
            None,
            None,
            &mut rng,
        )
        .unwrap();
    OcspResponse::successful(&basic).verify(&ca).unwrap();
    checked += 1;

    assert!(checked >= 3, "only {checked} round-trips checked");
}

#[test]
fn negative_cases_are_rejected() {
    let ca = certificate(CA_PEM);
    let leaf = certificate(LEAF_PEM);
    let response = OcspResponse::parse(RESPONSE_GOOD).unwrap();

    // Tampered signature.
    let mut basic = response.basic().unwrap();
    basic.signature[0] ^= 0x01;
    assert!(OcspResponse::successful(&basic).verify(&ca).is_err());

    // Wrong issuer.
    assert!(response.verify(&leaf).is_err());

    // Wrong nonce.
    assert!(response.check_nonce(Some(b"not-the-nonce")).is_err());
    assert!(response.check_nonce(None).is_err());

    // Wrong certificate for the response entry.
    let revoked = certificate(REVOKED_PEM);
    let basic = response.basic().unwrap();
    assert!(!basic.tbs_response_data.responses[0]
        .matches(&revoked, &ca)
        .unwrap());

    // A delegated responder without the OCSP signing EKU.
    let bad = OcspResponse::parse(include_bytes!("data/pki/ocsp_response_bad_eku.der")).unwrap();
    assert!(bad.verify(&ca).is_err());
}

#[test]
fn openssl_cli_parses_crown_built_artifacts() {
    // Skip when the vendored OpenSSL CLI is not available.
    let root = PathBuf::from("/home/loongtao/crown-ref/openssl");
    let binary = root.join("apps").join("openssl");
    if !binary.is_file() {
        eprintln!("skipping: {} not found", binary.display());
        return;
    }

    let ca = certificate(CA_PEM);
    let leaf = certificate(LEAF_PEM);
    let mut rng = TestRng(1234);

    // Build a request and a response with crown.
    let mut request = OcspRequest::request_for(&leaf, &ca, Hash::Sha1).unwrap();
    request.set_nonce(b"openssl-interop");
    let basic = OcspResponder::for_certificate(
        &ca,
        private_key(CA_KEY_PEM),
        SignatureAlgorithm::Ecdsa(Hash::Sha256),
        false,
    )
    .unwrap()
    .respond(
        vec![SingleResponse::new(
            CertId::for_certificate(&leaf, &ca, Hash::Sha1).unwrap(),
            CertStatus::Good,
            produced_at(),
        )],
        produced_at(),
        None,
        Some(b"openssl-interop"),
        &mut rng,
    )
    .unwrap();
    let response = OcspResponse::successful(&basic);
    assert!(basic.verify(&ca).is_ok());

    let dir = std::env::temp_dir();
    let request_path = dir.join(format!("crown-ocsp-{}-request.der", std::process::id()));
    let response_path = dir.join(format!("crown-ocsp-{}-response.der", std::process::id()));
    std::fs::write(&request_path, request.encode()).unwrap();
    std::fs::write(&response_path, response.encode()).unwrap();

    let run = |args: &[&OsStr]| -> std::process::Output {
        std::process::Command::new(&binary)
            .args(args)
            .env("LD_LIBRARY_PATH", &root)
            .env("OPENSSL_CONF", root.join("apps").join("openssl.cnf"))
            .output()
            .expect("run vendored openssl")
    };

    let output = run(&[
        OsStr::new("ocsp"),
        OsStr::new("-reqin"),
        request_path.as_os_str(),
        OsStr::new("-text"),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("OCSP Request Data")
            && stdout.contains("2F4AFF050669ADA5014AB2F358A7050A04160112"),
        "openssl did not parse the crown request:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = run(&[
        OsStr::new("ocsp"),
        OsStr::new("-respin"),
        response_path.as_os_str(),
        OsStr::new("-text"),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("OCSP Response Status: successful")
            && stdout.contains("Cert Status: good")
            && stdout.contains("OCSP Nonce"),
        "openssl did not parse the crown response:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = std::fs::remove_file(&request_path);
    let _ = std::fs::remove_file(&response_path);
}
