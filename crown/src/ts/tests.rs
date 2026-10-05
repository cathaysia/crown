//! Unit tests for the `ts` module: ESS attributes and DER round trips.

use alloc::vec;
use alloc::vec::Vec;

use crate::asn1::der;
use crate::asn1::time::Asn1Time;
use crate::x509::algorithm::{AlgorithmIdentifier, Hash};
use crate::x509::cert::Certificate;
use crate::x509::extensions::GeneralName;
use crate::x509::name::Name;

use super::*;

const TSA_PEM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/pki/ts_tsa.pem"
));

fn tsa_certificate() -> Certificate {
    Certificate::from_pem(TSA_PEM).expect("parse fixture TSA certificate")
}

fn sample_time() -> Asn1Time {
    Asn1Time::new(2026, 10, 5, 12, 30, 45, false).expect("valid time")
}

#[test]
fn ess_cert_id_v2_round_trip() {
    let id = EsCertIdV2 {
        hash_algorithm: Some(AlgorithmIdentifier::with_null(
            ObjectIdentifier::new(crate::asn1::oid::OID_SHA256).expect("oid"),
        )),
        cert_hash: vec![0xaa; 32],
        issuer_serial: Some(IssuerSerial {
            issuer: vec![GeneralName::DirectoryName(Name::from_common_name(
                "Test CA",
            ))],
            serial: vec![0x01, 0x02, 0x03],
        }),
    };
    let encoded = id.encode();
    assert_eq!(
        EsCertIdV2::parse(&mut der::Reader::new(&encoded)).unwrap(),
        id
    );
    assert_eq!(id.hash().unwrap(), Hash::Sha256);

    // The default hash algorithm is omitted and reads back as SHA-256.
    let defaulted = EsCertIdV2 {
        hash_algorithm: None,
        ..id.clone()
    };
    let defaulted_der = defaulted.encode();
    assert!(defaulted_der.len() < encoded.len());
    let parsed = EsCertIdV2::parse(&mut der::Reader::new(&defaulted_der)).unwrap();
    assert_eq!(parsed.hash_algorithm, None);
    assert_eq!(parsed.hash().unwrap(), Hash::Sha256);
}

#[test]
fn signing_certificate_v2_attribute_round_trip() {
    let certificate = tsa_certificate();
    let signing = SigningCertificateV2::from_certificate(&certificate).unwrap();
    assert!(signing.matches_certificate(&certificate).unwrap());

    let attribute = signing.to_attribute();
    assert!(attribute.oid.matches(OID_ID_AA_SIGNING_CERTIFICATE_V2));
    let parsed = SigningCertificateV2::from_attribute(&attribute).unwrap();
    assert_eq!(parsed, signing);

    // A wrong hash (or issuer/serial) must not match.
    let mut tampered = signing.clone();
    tampered.certs[0].cert_hash[0] ^= 1;
    assert!(!tampered.matches_certificate(&certificate).unwrap());
    let mut wrong_issuer = signing;
    wrong_issuer.certs[0].issuer_serial = Some(IssuerSerial {
        issuer: vec![GeneralName::DirectoryName(Name::from_common_name(
            "Other CA",
        ))],
        serial: vec![1],
    });
    assert!(!wrong_issuer.matches_certificate(&certificate).unwrap());
}

#[test]
fn signing_certificate_v1_attribute_round_trip() {
    let certificate = tsa_certificate();
    let signing = SigningCertificate::from_certificate(&certificate).unwrap();
    assert_eq!(signing.certs[0].cert_hash.len(), 20);
    assert!(signing.matches_certificate(&certificate).unwrap());
    let parsed = SigningCertificate::from_attribute(&signing.to_attribute()).unwrap();
    assert_eq!(parsed, signing);
}

#[test]
fn tst_info_round_trip() {
    let info = TstInfo {
        version: 1,
        policy: ObjectIdentifier::from_dotted_string("1.2.3.4.1").unwrap(),
        message_imprint: MessageImprint::for_data(b"crown timestamp payload", Hash::Sha512)
            .unwrap(),
        serial_number: vec![0x0b, 0xad],
        gen_time: sample_time(),
        accuracy: Some(Accuracy {
            seconds: Some(1),
            millis: Some(500),
            micros: Some(100),
        }),
        ordering: true,
        nonce: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        tsa: Some(GeneralName::DirectoryName(Name::from_common_name(
            "Test TSA",
        ))),
        extensions: Some(vec![crate::x509::extensions::Extension::new(
            ObjectIdentifier::from_dotted_string("1.2.3.4.99").unwrap(),
            false,
            der::octet_string(b"value"),
        )]),
    };
    let encoded = info.encode();
    let parsed = TstInfo::parse(&encoded).unwrap();
    assert_eq!(parsed, info);
    assert_eq!(parsed.encode(), encoded);
    // genTime is always a GeneralizedTime.
    assert!(encoded.windows(2).any(|window| window == &[0x18, 0x0f][..]));
}

#[test]
fn accuracy_round_trip() {
    for accuracy in [
        Accuracy::default(),
        Accuracy {
            seconds: Some(5),
            millis: None,
            micros: None,
        },
        Accuracy {
            seconds: None,
            millis: Some(999),
            micros: Some(1),
        },
    ] {
        let encoded = accuracy.encode();
        assert_eq!(
            Accuracy::parse(&mut der::Reader::new(&encoded)).unwrap(),
            accuracy
        );
    }
    // Out-of-range components are rejected.
    let bad = der::sequence(&der::implicit(0, false, &[0x03, 0xe8])); // millis = 1000
    assert!(Accuracy::parse(&mut der::Reader::new(&bad)).is_err());
}

#[test]
fn time_stamp_req_round_trip() {
    let mut request =
        TimeStampReq::for_data(b"crown timestamp payload", Hash::Sha256, true).unwrap();
    request.nonce = Some(vec![0x01, 0x02, 0x03, 0x04]);
    request.req_policy = Some(ObjectIdentifier::from_dotted_string("1.2.3.4.1").unwrap());
    let encoded = request.encode();
    let parsed = TimeStampReq::parse(&encoded).unwrap();
    assert_eq!(parsed, request);
    assert!(parsed
        .verify_message_imprint(b"crown timestamp payload")
        .unwrap());
    assert!(!parsed.verify_message_imprint(b"other payload").unwrap());

    let pem = request.to_pem();
    assert!(pem.starts_with("-----BEGIN TIME STAMP REQUEST-----"));
    assert_eq!(TimeStampReq::from_pem(&pem).unwrap(), request);
    let mut other = request.clone();
    other.cert_req = false;
    assert_eq!(other.encode().len(), encoded.len() - 3);
}
