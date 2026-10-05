//! Unit tests for the OCSP (RFC 6960) support.
//!
//! The fixtures under `tests/data/pki` were generated with the vendored
//! OpenSSL 3.5.8 CLI; the existing `ec.pem` / `ec_pkcs8.pem` self-signed CA
//! acts as the OCSP issuer:
//!
//! ```text
//! openssl x509 -req -in leaf.csr -CA ec.pem -CAkey ec_pkcs8.pem \
//!     -CAcreateserial -extfile leaf_ext.cnf -extensions leaf -out ocsp_leaf.pem
//! openssl ocsp -issuer ec.pem -cert ocsp_leaf.pem -reqout ocsp_request.der
//! openssl ocsp -index index.txt -CA ec.pem -rsigner ec.pem -rkey ec_pkcs8.pem \
//!     -reqin ocsp_request.der -respout ocsp_response_good.der -ndays 7
//! openssl ocsp -index index.txt -CA ec.pem -rsigner ocsp_responder.pem \
//!     -rkey rsa_pkcs8.pem -reqin ocsp_request.der \
//!     -respout ocsp_response_delegated.der -ndays 7
//! ```

use alloc::vec;

use crate::asn1::pem;
use crate::asn1::time::Asn1Time;
use crate::ocsp::{
    CertId, CertStatus, CrlReason, OcspRequest, OcspResponder, OcspResponse, OcspResponseStatus,
    ResponderId, SingleResponse,
};
use crate::x509::algorithm::{Hash, SignatureAlgorithm};
use crate::x509::cert::Certificate;
use crate::x509::keys::{PrivateKey, PrivateKeyInfo};

const REQUEST: &[u8] = include_bytes!("../../tests/data/pki/ocsp_request.der");
const REQUEST_REVOKED: &[u8] = include_bytes!("../../tests/data/pki/ocsp_request_revoked.der");
const REQUEST_SHA256: &[u8] = include_bytes!("../../tests/data/pki/ocsp_request_sha256.der");
const RESPONSE_GOOD: &[u8] = include_bytes!("../../tests/data/pki/ocsp_response_good.der");
const RESPONSE_REVOKED: &[u8] = include_bytes!("../../tests/data/pki/ocsp_response_revoked.der");
const RESPONSE_DELEGATED: &[u8] =
    include_bytes!("../../tests/data/pki/ocsp_response_delegated.der");
const RESPONSE_BYKEY: &[u8] = include_bytes!("../../tests/data/pki/ocsp_response_bykey.der");
const RESPONSE_BAD_EKU: &[u8] = include_bytes!("../../tests/data/pki/ocsp_response_bad_eku.der");

const CA_PEM: &str = include_str!("../../tests/data/pki/ec.pem");
const CA_KEY_PEM: &str = include_str!("../../tests/data/pki/ec_pkcs8.pem");
const LEAF_PEM: &str = include_str!("../../tests/data/pki/ocsp_leaf.pem");
const REVOKED_PEM: &str = include_str!("../../tests/data/pki/ocsp_revoked.pem");
const RESPONDER_PEM: &str = include_str!("../../tests/data/pki/ocsp_responder.pem");
const RESPONDER_KEY_PEM: &str = include_str!("../../tests/data/pki/rsa_pkcs8.pem");

/// Deterministic non-cryptographic RNG for the signing tests (the same
/// pattern as the PKCS#7 tests).
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

/// A producedAt inside every fixture's validity window.
fn produced_at() -> Asn1Time {
    Asn1Time::parse_generalized(b"20261005150000Z").expect("static time")
}

#[test]
fn openssl_request_parses_and_matches() {
    let ca = certificate(CA_PEM);
    let leaf = certificate(LEAF_PEM);
    let revoked = certificate(REVOKED_PEM);

    let request = OcspRequest::parse(REQUEST).unwrap();
    assert!(request.version.is_none());
    assert_eq!(request.requests.len(), 1);
    assert_eq!(request.encode(), REQUEST);

    let cert_id = request.cert_id().unwrap();
    assert_eq!(cert_id.hash().unwrap(), Hash::Sha1);
    assert_eq!(
        cert_id.issuer_name_hash,
        hex::decode("3D8562F5592C70AB7D4C3F6A746FA75DD477D2A7").unwrap()
    );
    assert_eq!(
        cert_id.issuer_key_hash,
        hex::decode("80337865393CCF93F46E753A2B5EDC1A912CF6B7").unwrap()
    );
    assert!(cert_id.matches(&leaf, &ca).unwrap());
    assert!(!cert_id.matches(&revoked, &ca).unwrap());

    let nonce = request.nonce().unwrap().expect("request nonce");
    assert_eq!(nonce.len(), 16);
}

#[test]
fn openssl_sha256_request_uses_sha256() {
    let ca = certificate(CA_PEM);
    let leaf = certificate(LEAF_PEM);
    let request = OcspRequest::parse(REQUEST_SHA256).unwrap();
    assert_eq!(request.encode(), REQUEST_SHA256);
    let cert_id = request.cert_id().unwrap();
    assert_eq!(cert_id.hash().unwrap(), Hash::Sha256);
    assert_eq!(cert_id.issuer_name_hash.len(), 32);
    assert!(cert_id.matches(&leaf, &ca).unwrap());
}

#[test]
fn request_build_and_pem_roundtrip() {
    let ca = certificate(CA_PEM);
    let leaf = certificate(LEAF_PEM);

    let mut request = OcspRequest::request_for(&leaf, &ca, Hash::Sha1).unwrap();
    let openssl = OcspRequest::parse(REQUEST).unwrap();
    assert_eq!(
        request.cert_id().unwrap().encode(),
        openssl.cert_id().unwrap().encode()
    );

    let fixture_nonce = hex::decode("FDE76DDCD4D41947C049CC859E7DB28C").unwrap();
    request.set_nonce(&fixture_nonce);
    assert_eq!(
        request.nonce().unwrap().as_deref(),
        Some(&fixture_nonce[..])
    );
    // With the same nonce, the built request is byte-identical to OpenSSL's.
    assert_eq!(request.encode(), REQUEST);

    let text = request.to_pem();
    assert!(text.starts_with("-----BEGIN OCSP REQUEST-----"));
    let parsed = OcspRequest::from_pem(&text).unwrap();
    assert_eq!(parsed.encode(), request.encode());

    request.clear_nonce();
    assert!(request.nonce().unwrap().is_none());
}

#[test]
fn openssl_good_response_parses_and_verifies() {
    let ca = certificate(CA_PEM);
    let leaf = certificate(LEAF_PEM);
    let revoked = certificate(REVOKED_PEM);

    let response = OcspResponse::parse(RESPONSE_GOOD).unwrap();
    assert_eq!(response.status, OcspResponseStatus::Successful);
    assert_eq!(response.status.name(), "successful");
    assert!(response.status.text().contains("successfully"));
    assert_eq!(response.encode(), RESPONSE_GOOD);

    let basic = response.basic().unwrap();
    assert_eq!(basic.tbs_response_data.version, None);
    assert_eq!(
        basic.tbs_response_data.responder_id,
        ResponderId::ByName(ca.subject().clone())
    );
    assert_eq!(basic.certs.len(), 1);

    let single = &basic.tbs_response_data.responses[0];
    assert_eq!(single.cert_status, CertStatus::Good);
    assert!(single.next_update.is_some());
    assert!(single.matches(&leaf, &ca).unwrap());
    assert!(!single.matches(&revoked, &ca).unwrap());

    response.verify(&ca).unwrap();
    response
        .check_request_nonce(&OcspRequest::parse(REQUEST).unwrap())
        .unwrap();
    assert_eq!(response.nonce().unwrap().unwrap().len(), 16);
}

#[test]
fn openssl_revoked_response_reports_reason() {
    let ca = certificate(CA_PEM);
    let revoked = certificate(REVOKED_PEM);

    let response = OcspResponse::parse(RESPONSE_REVOKED).unwrap();
    let basic = response.basic().unwrap();
    let single = &basic.tbs_response_data.responses[0];
    assert!(single.matches(&revoked, &ca).unwrap());
    match &single.cert_status {
        CertStatus::Revoked {
            revocation_reason,
            revocation_time,
        } => {
            assert_eq!(*revocation_reason, Some(CrlReason::KeyCompromise));
            assert_eq!(
                *revocation_time,
                Asn1Time::parse_generalized(b"20261005143800Z").unwrap()
            );
        }
        other => panic!("unexpected status {other:?}"),
    }
    response.verify(&ca).unwrap();
    assert!(response
        .check_request_nonce(&OcspRequest::parse(REQUEST_REVOKED).unwrap())
        .is_ok());
    assert!(response
        .check_request_nonce(&OcspRequest::parse(REQUEST).unwrap())
        .is_err());
}

#[test]
fn openssl_delegated_response_verifies_with_eku() {
    let ca = certificate(CA_PEM);
    let responder = certificate(RESPONDER_PEM);
    let bad_responder = certificate(include_str!("../../tests/data/pki/ocsp_responder_bad.pem"));

    let response = OcspResponse::parse(RESPONSE_DELEGATED).unwrap();
    response.verify(&ca).unwrap();
    response
        .verify_with_responder(&ca, Some(&responder))
        .unwrap();

    // An explicit certificate that does not match the responder id fails.
    let mismatched = response.verify_with_responder(&ca, Some(&bad_responder));
    assert!(mismatched.is_err());

    // A delegated responder without the OCSP signing EKU is rejected even
    // though its certificate chains to the issuer.
    let bad = OcspResponse::parse(RESPONSE_BAD_EKU).unwrap();
    let error = bad.verify(&ca).unwrap_err();
    assert!(
        error.to_string().contains("OCSP signing"),
        "unexpected error: {error}"
    );
}

#[test]
fn by_key_responder_id_parses_and_verifies() {
    let ca = certificate(CA_PEM);
    let response = OcspResponse::parse(RESPONSE_BYKEY).unwrap();
    let expected = Hash::Sha1
        .digest(&ca.subject_public_key_info().key)
        .unwrap();
    let basic = response.basic().unwrap();
    assert_eq!(
        basic.tbs_response_data.responder_id,
        ResponderId::ByKey(expected)
    );
    assert!(basic
        .tbs_response_data
        .responder_id
        .matches_certificate(&ca)
        .unwrap());
    response.verify(&ca).unwrap();
}

#[test]
fn crown_signed_response_roundtrips_and_verifies() {
    let ca = certificate(CA_PEM);
    let leaf = certificate(LEAF_PEM);
    let ca_key = private_key(CA_KEY_PEM);
    let mut rng = TestRng(7);

    let cert_id = CertId::for_certificate(&leaf, &ca, Hash::Sha256).unwrap();
    let single = SingleResponse::new(cert_id, CertStatus::Good, produced_at());
    let responder =
        OcspResponder::for_certificate(&ca, ca_key, SignatureAlgorithm::Ecdsa(Hash::Sha256), false)
            .unwrap();
    let basic = responder
        .respond(
            vec![single],
            produced_at(),
            Some(Asn1Time::parse_utc(b"261012150000Z").unwrap()),
            Some(b"a-fresh-nonce-42"),
            &mut rng,
        )
        .unwrap();
    basic.verify(&ca).unwrap();
    assert_eq!(
        basic.nonce().unwrap().as_deref(),
        Some(&b"a-fresh-nonce-42"[..])
    );

    let response = OcspResponse::successful(&basic);
    response.check_nonce(Some(b"a-fresh-nonce-42")).unwrap();
    let der = response.encode();
    let parsed = OcspResponse::parse(&der).unwrap();
    parsed.verify(&ca).unwrap();
    assert_eq!(parsed.encode(), der);
    assert_eq!(parsed.basic().unwrap().certs.len(), 1);

    let text = response.to_pem();
    assert!(text.starts_with("-----BEGIN OCSP RESPONSE-----"));
    let from_pem = OcspResponse::from_pem(&text).unwrap();
    assert_eq!(from_pem.encode(), der);
    from_pem.verify(&ca).unwrap();
}

#[test]
fn crown_signed_delegated_response_verifies() {
    let ca = certificate(CA_PEM);
    let leaf = certificate(LEAF_PEM);
    let responder_cert = certificate(RESPONDER_PEM);
    let responder_key = private_key(RESPONDER_KEY_PEM);
    let mut rng = TestRng(11);

    let cert_id = CertId::for_certificate(&leaf, &ca, Hash::Sha1).unwrap();
    let single = SingleResponse::new(cert_id, CertStatus::Good, produced_at());
    let responder = OcspResponder::for_certificate(
        &responder_cert,
        responder_key,
        SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
        true,
    )
    .unwrap();
    assert!(matches!(responder.responder_id, ResponderId::ByKey(_)));
    let basic = responder
        .respond(vec![single], produced_at(), None, None, &mut rng)
        .unwrap();
    assert!(basic.nonce().unwrap().is_none());
    basic.verify(&ca).unwrap();
    OcspResponse::successful(&basic).verify(&ca).unwrap();
}

#[test]
fn negative_verification_cases() {
    let ca = certificate(CA_PEM);
    let leaf = certificate(LEAF_PEM);

    // A tampered signature must not verify.
    let response = OcspResponse::parse(RESPONSE_GOOD).unwrap();
    let mut basic = response.basic().unwrap();
    basic.signature[0] ^= 0x80;
    let tampered = OcspResponse::successful(&basic);
    assert!(tampered.verify(&ca).is_err());

    // A wrong issuer must not verify.
    assert!(response.verify(&leaf).is_err());

    // The wrong nonce must not verify.
    assert!(response.check_nonce(Some(b"bogus")).is_err());
    assert!(response.check_nonce(None).is_err());

    // A response without a nonce does not satisfy a request that has one.
    let mut rng = TestRng(3);
    let responder = OcspResponder::for_certificate(
        &ca,
        private_key(CA_KEY_PEM),
        SignatureAlgorithm::Ecdsa(Hash::Sha256),
        false,
    )
    .unwrap();
    let basic = responder
        .respond(
            vec![SingleResponse::new(
                CertId::for_certificate(&leaf, &ca, Hash::Sha1).unwrap(),
                CertStatus::Good,
                produced_at(),
            )],
            produced_at(),
            None,
            None,
            &mut rng,
        )
        .unwrap();
    let no_nonce = OcspResponse::successful(&basic);
    assert!(no_nonce.check_nonce(None).is_ok());
    assert!(no_nonce.check_nonce(Some(b"expected")).is_err());
}

#[test]
fn response_status_values() {
    let cases = [
        (0u8, OcspResponseStatus::Successful, "successful"),
        (1, OcspResponseStatus::MalformedRequest, "malformedRequest"),
        (2, OcspResponseStatus::InternalError, "internalError"),
        (3, OcspResponseStatus::TryLater, "tryLater"),
        (5, OcspResponseStatus::SigRequired, "sigRequired"),
        (6, OcspResponseStatus::Unauthorized, "unauthorized"),
    ];
    for (value, status, name) in cases {
        assert_eq!(OcspResponseStatus::from_u8(value).unwrap(), status);
        assert_eq!(status.as_u8(), value);
        assert_eq!(status.name(), name);
        assert!(!status.text().is_empty());
    }
    assert!(OcspResponseStatus::from_u8(4).is_err());
}

#[test]
fn crl_reason_values() {
    let reasons = [
        CrlReason::Unspecified,
        CrlReason::KeyCompromise,
        CrlReason::CaCompromise,
        CrlReason::AffiliationChanged,
        CrlReason::Superseded,
        CrlReason::CessationOfOperation,
        CrlReason::CertificateHold,
        CrlReason::RemoveFromCrl,
        CrlReason::PrivilegeWithdrawn,
        CrlReason::AaCompromise,
    ];
    for reason in reasons {
        assert_eq!(CrlReason::from_u8(reason.as_u8()).unwrap(), reason);
        assert!(!reason.name().is_empty());
    }
    assert!(CrlReason::from_u8(7).is_err());

    // Every reason round-trips through a CertStatus encoding.
    let ca = certificate(CA_PEM);
    let leaf = certificate(LEAF_PEM);
    let cert_id = CertId::for_certificate(&leaf, &ca, Hash::Sha1).unwrap();
    for reason in reasons {
        let status = CertStatus::Revoked {
            revocation_time: produced_at(),
            revocation_reason: Some(reason),
        };
        let single = SingleResponse::new(cert_id.clone(), status.clone(), produced_at());
        let encoded = single.encode();
        let mut reader = crate::asn1::der::Reader::new(&encoded);
        let parsed = SingleResponse::parse(&mut reader).unwrap();
        assert_eq!(parsed.cert_status, status);
    }
}
