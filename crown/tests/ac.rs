//! Attribute certificate (RFC 5755) fixtures copied from the OpenSSL tree.

use crown::x509::ac::AttributeCertificate;

const BASE: &str = "tests/data/pki/";

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{BASE}{name}")).unwrap_or_else(|err| panic!("read {name}: {err}"))
}

fn read_text(name: &str) -> String {
    String::from_utf8(read(name)).unwrap_or_else(|err| panic!("utf8 {name}: {err}"))
}

#[test]
fn openssl_attribute_certificates_parse_and_reencode() {
    let files = [
        "ac_acert.pem",
        "ac_acert_ietf.pem",
        "ac_acert_bc1.pem",
        "ac_acert_bc2.pem",
    ];
    let mut parsed = 0;
    let mut reencoded = 0;
    for file in files {
        let text = read_text(file);
        let certificate = match AttributeCertificate::from_pem(&text) {
            Ok(certificate) => certificate,
            Err(error) => panic!("{file}: {error}"),
        };
        assert!(!certificate.serial_number().is_empty(), "{file}");
        assert_eq!(certificate.info().version, 1, "{file}");
        parsed += 1;
        let der = match crown::asn1::pem::parse_first(&text) {
            Ok(block) => block.data,
            Err(error) => panic!("{file}: {error}"),
        };
        if certificate.encode() == der {
            reencoded += 1;
        } else {
            let first_diff = certificate
                .encode()
                .iter()
                .zip(der.iter())
                .position(|(left, right)| left != right);
            println!(
                "{file}: re-encode differs at {first_diff:?} (lens {} vs {})",
                certificate.encode().len(),
                der.len()
            );
        }
    }
    assert!(parsed >= 4, "only {parsed} attribute certificates parsed");
    assert!(
        reencoded >= 4,
        "only {reencoded} attribute certificates re-encoded byte-exactly"
    );
}

/// A deterministic RNG for the signing test.
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
fn attribute_certificate_sign_and_verify() {
    use crown::asn1::oid::ObjectIdentifier;
    use crown::asn1::time::Asn1Time;
    use crown::ec::CurveId;
    use crown::x509::ac::{
        attr, attribute_from_text, AttCertIssuer, AttCertValidityPeriod, AttributeCertificate,
        AttributeCertificateInfo, Holder, V2Form,
    };
    use crown::x509::{
        extensions::basic_constraints, Certificate, Hash, Name, PrivateKey, SignatureAlgorithm,
    };

    let mut rng = TestRng(0xac);
    let (scalar, _) = crown::ecdh::generate(CurveId::P256, &mut rng).expect("keygen");
    let key = PrivateKey::Ec {
        curve: CurveId::P256,
        scalar,
    };
    let algorithm = SignatureAlgorithm::Ecdsa(Hash::Sha256);
    let now = 1_700_000_000;
    let not_before = Asn1Time::from_unix(now - 60, false);
    let not_after = Asn1Time::from_unix(now + 86_400, false);
    let holder_name = Name::from_common_name("AC Holder");
    let holder_certificate = Certificate::self_signed(
        holder_name.clone(),
        algorithm,
        &key,
        not_before,
        not_after,
        vec![basic_constraints(false, None)],
        &mut rng,
    )
    .expect("holder certificate");

    let info = AttributeCertificateInfo::build(
        Holder {
            base_certificate_id: None,
            entity_name: Some(vec![crown::x509::GeneralName::DirectoryName(
                holder_certificate.subject().clone(),
            )]),
            object_digest_info: None,
        },
        AttCertIssuer::V2(V2Form {
            issuer_name: Some(vec![crown::x509::GeneralName::DirectoryName(
                holder_certificate.subject().clone(),
            )]),
            ..Default::default()
        }),
        vec![7],
        AttCertValidityPeriod {
            not_before,
            not_after,
        },
        vec![attribute_from_text(attr::ROLE, &["auditor"])],
        Vec::new(),
        algorithm,
    );
    let certificate = AttributeCertificate::sign(info, &key, &mut rng).expect("sign AC");
    assert_eq!(certificate.serial_number(), &[7]);
    assert!(certificate.is_valid_at(now));
    assert!(!certificate.is_valid_at(now + 200_000));
    assert!(certificate.holder_matches(&holder_certificate));
    certificate
        .verify(&holder_certificate, Some(now))
        .expect("AC verifies");

    let role = certificate.info().attribute(attr::ROLE).expect("role");
    assert_eq!(role.oid, ObjectIdentifier::new(attr::ROLE).unwrap());

    // Round trip through DER/PEM.
    let der = certificate.encode();
    let reparsed = AttributeCertificate::parse(&der).expect("parse own AC");
    assert_eq!(reparsed.encode(), der);
    assert_eq!(
        AttributeCertificate::from_pem(&certificate.to_pem())
            .expect("pem")
            .encode(),
        der
    );

    // The wrong issuer fails, and a tampered serial fails the signature.
    let other_key = {
        let (scalar, _) = crown::ecdh::generate(CurveId::P256, &mut rng).expect("keygen");
        PrivateKey::Ec {
            curve: CurveId::P256,
            scalar,
        }
    };
    let other_certificate = Certificate::self_signed(
        Name::from_common_name("Other"),
        algorithm,
        &other_key,
        not_before,
        not_after,
        Vec::new(),
        &mut rng,
    )
    .expect("other certificate");
    assert!(certificate.verify(&other_certificate, Some(now)).is_err());

    let mut tampered = der.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let parsed = AttributeCertificate::parse(&tampered).expect("still parses");
    assert!(!parsed
        .verify_signature(holder_certificate.public_key())
        .unwrap_or(true));
}
