//! Unit tests for the CRMF structures.

use alloc::vec;

use super::*;
use crate::asn1::oid;

const RSA_KEY_PEM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/pki/rsa_pkcs8.pem"
));

fn rsa_key() -> PrivateKey {
    let der = crate::asn1::pem::parse_first(RSA_KEY_PEM)
        .expect("pem")
        .data;
    crate::x509::keys::PrivateKeyInfo::parse(&der)
        .expect("pkcs8")
        .decode()
        .expect("decode")
}

fn template() -> CertTemplate {
    let key = rsa_key();
    let spki = SubjectPublicKeyInfo::from_public_key(&key.public_key().expect("public")).unwrap();
    CertTemplate {
        version: Some(2),
        serial_number: Some(vec![0x01, 0x02, 0x03]),
        signing_alg: Some(SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256).to_identifier()),
        issuer: Some(Name::from_common_name("Test CA")),
        validity: OptionalValidity::new()
            .with_not_before(Asn1Time::new(2024, 1, 2, 3, 4, 5, true).unwrap())
            .with_not_after(Asn1Time::new(2026, 1, 2, 3, 4, 5, false).unwrap()),
        subject: Some(Name::from_common_name("Test")),
        public_key: Some(spki),
        issuer_uid: Some(vec![0xaa, 0xbb]),
        subject_uid: Some(vec![0xcc]),
        extensions: vec![Extension::new(
            ObjectIdentifier::new(oid::OID_BASIC_CONSTRAINTS).unwrap(),
            true,
            der::sequence(&der::boolean(true)),
        )],
    }
}

#[test]
fn cert_template_round_trip() {
    let template = template();
    let der = template.encode();
    let parsed = CertTemplate::parse(&der).expect("parse");
    assert_eq!(parsed, template);
    assert_eq!(parsed.encode(), der);
}

#[test]
fn empty_cert_template_round_trips() {
    let template = CertTemplate::new();
    let der = template.encode();
    assert_eq!(der, vec![0x30, 0x00]);
    assert_eq!(CertTemplate::parse(&der).unwrap(), template);
}

#[test]
fn cert_request_messages_with_signature_popo() {
    let key = rsa_key();
    let public = key.public_key().unwrap();
    let mut msg = CertReqMsg::for_key_identifier(
        &public,
        Some(Name::from_common_name("Test CA")),
        Name::from_common_name("Test"),
    )
    .unwrap();
    msg.reg_info
        .push(AttributeTypeAndValue::cert_request(&msg.cert_req));
    msg.sign_popo(
        &key,
        SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
        &mut TestRng(7),
    )
    .unwrap();

    let messages = CertReqMessages::new(vec![msg.clone()]);
    let der = messages.encode();
    let parsed = CertReqMessages::parse(&der).expect("parse");
    assert_eq!(parsed.messages.len(), 1);
    assert_eq!(parsed.messages[0].cert_req, msg.cert_req);
    assert_eq!(parsed.messages[0], msg);
    assert_eq!(parsed.encode(), der);

    // The POP signature covers the DER of the CertRequest.
    assert_eq!(msg.verify_popo().unwrap(), Some(true));

    // Tampering with the template invalidates the POP.
    let mut tampered = parsed;
    tampered.messages[0].cert_req.cert_template.subject = Some(Name::from_common_name("Mallory"));
    assert_eq!(tampered.messages[0].verify_popo().unwrap(), Some(false));

    // The embedded regInfo certReq value parses back.
    let embedded = tampered.messages[0].reg_info[0]
        .cert_request_value()
        .unwrap()
        .expect("certReq");
    assert_eq!(
        embedded.cert_template.subject,
        msg.cert_req.cert_template.subject
    );
}

#[test]
fn ra_verified_and_key_encipherment_popo_round_trip() {
    let key = rsa_key();
    let public = key.public_key().unwrap();
    let mut msg =
        CertReqMsg::for_key_identifier(&public, None, Name::from_common_name("K")).unwrap();
    msg.popo = Some(ProofOfPossession::RaVerified);
    let der = msg.encode();
    assert_eq!(CertReqMsg::parse(&der).unwrap(), msg);

    let mac = PKMACValue::new(
        AlgorithmIdentifier::new(
            ObjectIdentifier::new(OID_ID_PASSWORD_BASED_MAC).unwrap(),
            Some(PbmParameter::new(vec![7; 16], Hash::Sha256, 100, Hash::Sha256).encode()),
        ),
        vec![0x11, 0x22, 0x33],
    );
    for priv_key in [
        PopoPrivKey::SubsequentMessage(1),
        PopoPrivKey::DhMac(vec![1, 2, 3]),
        PopoPrivKey::AgreeMac(mac.clone()),
        PopoPrivKey::EncryptedKey(der::sequence(&der::null())),
    ] {
        msg.popo = Some(ProofOfPossession::KeyEncipherment(priv_key.clone()));
        let der = msg.encode();
        let parsed = CertReqMsg::parse(&der).unwrap_or_else(|err| panic!("{priv_key:?}: {err:?}"));
        assert_eq!(
            parsed.popo,
            Some(ProofOfPossession::KeyEncipherment(priv_key))
        );
        assert_eq!(parsed.encode(), der);
    }
}

#[test]
fn pbm_parameter_round_trip_and_key_derivation() {
    let params = PbmParameter::new(vec![0x5a; 16], Hash::Sha256, 500, Hash::Sha1);
    let der = params.encode();
    let parsed = PbmParameter::parse(&der).expect("parse");
    assert_eq!(parsed, params);

    // Derivation is deterministic and follows RFC 4210 5.1.3.1.
    let key = params.derive_key(b"secret").unwrap();
    let mut expected = Hash::Sha256
        .digest(&[b"secret".as_slice(), &[0x5a; 16]].concat())
        .unwrap();
    for _ in 1..500 {
        expected = Hash::Sha256.digest(&expected).unwrap();
    }
    assert_eq!(key, expected);
    assert_eq!(params.mac(b"secret", b"message").unwrap().len(), 20);
}

#[test]
fn encrypted_value_round_trip() {
    let value = EncryptedValue {
        intended_alg: Some(SignatureAlgorithm::Ecdsa(Hash::Sha256).to_identifier()),
        symm_alg: Some(AlgorithmIdentifier::with_null(
            ObjectIdentifier::new(oid::OID_AES_256_CBC).unwrap(),
        )),
        enc_symm_key: Some(vec![1, 2, 3, 4]),
        key_alg: None,
        value_hint: Some(b"hint".to_vec()),
        enc_value: vec![9; 32],
    };
    let der = value.encode();
    assert_eq!(EncryptedValue::parse(&der).unwrap(), value);

    let key = EncryptedKey::EncryptedValue(value);
    let encoded = key.encode();
    let mut reader = Reader::new(&encoded);
    assert_eq!(EncryptedKey::parse(&mut reader).unwrap(), key);

    let enveloped = EncryptedKey::EnvelopedData(der::sequence(&der::integer(&[1])));
    let encoded = enveloped.encode();
    let mut reader = Reader::new(&encoded);
    assert_eq!(EncryptedKey::parse(&mut reader).unwrap(), enveloped);
}

/// A tiny deterministic generator for POPO signing.
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
