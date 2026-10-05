//! Unit tests for the CMP message layer.

use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::crmf::{CertReqMessages, CertReqMsg};
use crate::x509::keys::PrivateKeyInfo;
use crate::x509::name::Name;

const RSA_KEY_PEM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/pki/rsa_pkcs8.pem"
));

struct TestRng(u64);

impl Rng for TestRng {
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

fn rsa_key() -> PrivateKey {
    let der = crate::asn1::pem::parse_first(RSA_KEY_PEM)
        .expect("pem")
        .data;
    PrivateKeyInfo::parse(&der)
        .expect("pkcs8")
        .decode()
        .expect("decode")
}

fn header() -> PkiHeader {
    let mut header = PkiHeader::new(
        GeneralName::DirectoryName(Name::from_common_name("Test")),
        GeneralName::DirectoryName(Name::from_common_name("Test CA")),
    );
    header.message_time = Some(Asn1Time::new(2026, 1, 2, 3, 4, 5, false).unwrap());
    header.transaction_id = Some(vec![7; 16]);
    header.sender_nonce = Some(vec![8; 16]);
    header
}

fn ir_body(key: &PrivateKey) -> PkiBody {
    let message = CertReqMsg::for_key_identifier(
        &key.public_key().unwrap(),
        None,
        Name::from_common_name("Test"),
    )
    .unwrap();
    PkiBody::Ir(CertReqMessages::new(vec![message]))
}

#[test]
fn error_and_pkiconf_bodies_round_trip() {
    let mut status = PkiStatusInfo::new(PKI_STATUS_REJECTION);
    status.status_string.push("bad request".into());
    status.fail_info = Some(vec![0x40]); // badRequest (bit 2)
    let body = PkiBody::Error(ErrorMsgContent {
        pki_status_info: status,
        error_code: Some(7),
        error_details: vec!["detail".into()],
    });
    let message = PkiMessage::new(header(), body);
    let der = message.encode();
    let parsed = PkiMessage::parse(&der).expect("parse");
    assert_eq!(parsed, message);
    assert_eq!(parsed.encode(), der);

    let body = PkiBody::CertConf(CertConfirmContent {
        statuses: vec![CertStatus::new(vec![0xaa; 32], Vec::new())],
    });
    let message = PkiMessage::new(header(), body);
    let der = message.encode();
    assert_eq!(PkiMessage::parse(&der).unwrap(), message);

    let message = PkiMessage::new(header(), PkiBody::Pkiconf);
    let der = message.encode();
    assert_eq!(PkiMessage::parse(&der).unwrap(), message);

    let message = PkiMessage::new(
        header(),
        PkiBody::PollReq(PollReqContent {
            requests: vec![PollReq::new(Vec::new())],
        }),
    );
    let der = message.encode();
    assert_eq!(PkiMessage::parse(&der).unwrap(), message);

    let message = PkiMessage::new(
        header(),
        PkiBody::PollRep(PollRepContent {
            responses: vec![PollRep::new(vec![1], 5)],
        }),
    );
    let der = message.encode();
    assert_eq!(PkiMessage::parse(&der).unwrap(), message);

    // Unknown body tags survive a round trip.
    let mut other = PkiMessage::new(
        header(),
        PkiBody::Other {
            tag: 1,
            value: der::sequence(&der::integer(&[1])),
        },
    );
    other.protection = None;
    let der = other.encode();
    let parsed = PkiMessage::parse(&der).unwrap();
    assert_eq!(parsed, other);
    assert_eq!(parsed.body.tag(), 1);
}

#[test]
fn password_protection_round_trip_and_tamper() {
    let key = rsa_key();
    let mut message = PkiMessage::new(header(), ir_body(&key));
    message
        .protect_password(b"secret", &mut TestRng(3))
        .unwrap();
    assert!(message.verify_password(b"secret").unwrap());
    assert!(!message.verify_password(b"wrong").unwrap());
    assert!(!message.verify_signature().unwrap());

    let der = message.encode();
    let parsed = PkiMessage::parse(&der).expect("parse");
    assert_eq!(parsed, message);
    assert!(parsed.verify_password(b"secret").unwrap());

    // Tampering with the body invalidates the MAC.
    let mut tampered = parsed.clone();
    if let PkiBody::Ir(messages) = &mut tampered.body {
        messages.messages[0].cert_req.cert_template.subject =
            Some(Name::from_common_name("Mallory"));
    } else {
        panic!("unexpected body");
    }
    let der = tampered.encode();
    let tampered = PkiMessage::parse(&der).unwrap();
    assert!(!tampered.verify_password(b"secret").unwrap());
}

#[test]
fn signature_protection_round_trip_and_tamper() {
    let key = rsa_key();
    let subject = Name::from_common_name("CMP Signer");
    let cert = Certificate::self_signed(
        subject,
        SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
        &key,
        Asn1Time::new(2024, 1, 1, 0, 0, 0, false).unwrap(),
        Asn1Time::new(2030, 1, 1, 0, 0, 0, false).unwrap(),
        Vec::new(),
        &mut TestRng(11),
    )
    .unwrap();

    let mut message = PkiMessage::new(header(), ir_body(&key));
    message
        .protect_signature(
            &cert,
            &key,
            SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
            &mut TestRng(13),
        )
        .unwrap();
    assert_eq!(message.extra_certs.len(), 1);
    assert!(message.verify_signature().unwrap());
    assert!(!message.verify_password(b"secret").unwrap());

    let der = message.encode();
    let parsed = PkiMessage::parse(&der).expect("parse");
    assert_eq!(parsed, message);
    assert!(parsed.verify_signature().unwrap());

    // Tampering with the header invalidates the signature.
    let mut tampered = parsed.clone();
    tampered.header.transaction_id = Some(vec![9; 16]);
    let der = tampered.encode();
    let tampered = PkiMessage::parse(&der).unwrap();
    assert!(!tampered.verify_signature().unwrap());
}

#[test]
fn header_general_info_helpers() {
    let mut header = header();
    assert!(!header.implicit_confirm());
    assert!(header.confirm_wait_time().unwrap().is_none());
    assert!(header.cert_profiles().unwrap().is_empty());
    assert!(header.ca_certs().unwrap().is_empty());

    header.set_general_info(InfoTypeAndValue::implicit_confirm());
    header.set_general_info(InfoTypeAndValue::confirm_wait_time(
        &Asn1Time::new(2026, 2, 3, 4, 5, 6, false).unwrap(),
    ));
    header.set_general_info(InfoTypeAndValue::cert_profile(&["profile-1"]));
    assert!(header.implicit_confirm());
    assert_eq!(header.confirm_wait_time().unwrap().unwrap().year, 2026);
    assert_eq!(header.cert_profiles().unwrap(), vec!["profile-1"]);

    let der = header.encode();
    let parsed = PkiHeader::parse(&mut Reader::new(&der)).unwrap();
    assert_eq!(parsed, header);
}

#[test]
fn status_values() {
    let mut status = PkiStatusInfo::new(PKI_STATUS_GRANTED_WITH_MODS);
    assert_eq!(status.status_name(), "grantedWithMods");
    assert!(!status.is_accepted());
    status.fail_info = Some(vec![0b1000_0000, 0b0000_0001]);
    assert_eq!(status.fail_info_names(), vec!["badAlg", "unacceptedPolicy"]);
    let der = status.encode();
    let parsed = PkiStatusInfo::parse(&mut Reader::new(&der)).unwrap();
    assert_eq!(parsed, status);
}

#[test]
fn pem_round_trip() {
    let key = rsa_key();
    let mut message = PkiMessage::new(header(), ir_body(&key));
    message.protect_password(b"pem", &mut TestRng(5)).unwrap();
    let pem = message.to_pem();
    assert!(pem.starts_with("-----BEGIN CMP MESSAGE-----"));
    assert_eq!(PkiMessage::from_pem(&pem).unwrap(), message);
}
