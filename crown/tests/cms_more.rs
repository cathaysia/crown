//! Golden tests for the CMS additions: `AuthenticatedData` and the
//! multi-signer `SignedData` builder, cross-checked with the OpenSSL 3.5.8
//! CLI where the CLI supports the structure.

use crown::cms::{AuthenticatedData, AuthenticatedDataBuilder, SignedDataMultiBuilder, SignerSpec};
use crown::pkcs7::Pkcs7;
use crown::x509::cert::Certificate;
use crown::x509::keys::PrivateKey;
use crown::x509::{Hash, SignatureAlgorithm};

const BASE: &str = "tests/data/pki/";

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{BASE}{name}")).unwrap_or_else(|err| panic!("read {name}: {err}"))
}

fn read_text(name: &str) -> String {
    String::from_utf8(read(name)).unwrap_or_else(|err| panic!("utf8 {name}: {err}"))
}

fn certificate(name: &str) -> Certificate {
    Certificate::from_pem(&read_text(name)).unwrap_or_else(|err| panic!("{name}: {err}"))
}

fn private_key(name: &str, _password: Option<&str>) -> PrivateKey {
    let bytes = read(name);
    let der = match core::str::from_utf8(&bytes) {
        Ok(text) if text.contains("-----BEGIN") => {
            crown::asn1::pem::parse_first(text)
                .unwrap_or_else(|err| panic!("{name}: {err}"))
                .data
        }
        _ => bytes,
    };
    crown::x509::PrivateKeyInfo::parse(&der)
        .unwrap_or_else(|err| panic!("{name}: {err}"))
        .decode()
        .unwrap_or_else(|err| panic!("{name}: {err}"))
}

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

/// Run the vendored OpenSSL CLI when it exists.
fn openssl(args: &[&str]) -> Option<std::process::Output> {
    let binary = std::env::var("CROWN_OPENSSL")
        .unwrap_or_else(|_| "/home/loongtao/crown-ref/openssl/apps/openssl".to_string());
    if !std::path::Path::new(&binary).exists() {
        eprintln!("openssl CLI not found at {binary}; skipping interop check");
        return None;
    }
    let mut command = std::process::Command::new(binary);
    command.env(
        "LD_LIBRARY_PATH",
        std::env::var("CROWN_OPENSSL_LIB")
            .unwrap_or_else(|_| "/home/loongtao/crown-ref/openssl".to_string()),
    );
    command.args(args);
    Some(
        command
            .output()
            .unwrap_or_else(|err| panic!("openssl: {err}")),
    )
}

#[test]
fn authenticated_data_round_trip() {
    let mut rng = TestRng(0xa11);
    let payload = read("payload.txt");
    let leaf = certificate("leaf.pem");

    // RSA recipient.
    let data = AuthenticatedDataBuilder::new(payload.clone())
        .add_rsa_recipient(&leaf)
        .build(&mut rng)
        .expect("build authdata");
    assert_eq!(data.mac.len(), 32);
    assert_eq!(data.version, 0);
    assert_eq!(data.auth_attrs.len(), 2);
    let key = private_key("rsa_pkcs8.pem", None);
    let content = data
        .verify_with_key(&key, &leaf)
        .expect("verify with RSA recipient");
    assert_eq!(content, payload);
    std::fs::write(
        std::env::temp_dir().join("crown-authdata-rsa.der"),
        data.to_content_info().encode(),
    )
    .expect("write rsa fixture");

    // Wrong key/recipient fails.
    let ec = certificate("ec.pem");
    assert!(data.verify_with_key(&key, &ec).is_err());

    // Password recipient.
    let data = AuthenticatedDataBuilder::new(payload.clone())
        .add_password_recipient(b"crown-test", 2048)
        .build(&mut rng)
        .expect("build password authdata");
    let content = data
        .verify_with_password(b"crown-test")
        .expect("verify with password");
    assert_eq!(content, payload);
    assert!(data.verify_with_password(b"wrong").is_err());

    // KEK recipient.
    let kek: Vec<u8> = (0u8..16).collect();
    let data = AuthenticatedDataBuilder::new(payload.clone())
        .add_kek_recipient(&kek, b"kek-1")
        .build(&mut rng)
        .expect("build kek authdata");
    assert_eq!(
        data.verify_with_kek(&kek, b"kek-1").expect("verify kek"),
        payload
    );

    // Round trips through ContentInfo/PEM.
    let der = data.to_content_info().encode();
    let info = crown::pkcs7::ContentInfo::parse(&der).expect("content info");
    let reparsed = AuthenticatedData::from_content_info(&info).expect("parse authdata");
    assert_eq!(reparsed.encode(), data.encode());
    let pem = data.to_pem();
    assert!(AuthenticatedData::from_pem(&pem).is_ok());

    // The DER is structurally valid for OpenSSL's ASN.1 parser.
    let path = std::env::temp_dir().join("crown-authdata.der");
    std::fs::write(&path, data.to_content_info().encode()).expect("write");
    if let Some(output) = openssl(&["asn1parse", "-inform", "DER", "-in", path.to_str().unwrap()]) {
        assert!(
            output.status.success(),
            "asn1parse failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let dump = String::from_utf8_lossy(&output.stdout);
        assert!(dump.contains("hmacWithSHA256"), "no HMAC algorithm in dump");
    }
}

#[test]
fn multi_signer_signed_data() {
    let mut rng = TestRng(0x51);
    let payload = read("payload.txt");
    let leaf = certificate("leaf.pem");
    let ec = certificate("ec.pem");
    let rsa_key = private_key("rsa_pkcs8.pem", None);
    let ec_key = private_key("ec_pkcs8.pem", None);

    let builder = SignedDataMultiBuilder::new(payload.clone())
        .add_signer(SignerSpec::new(
            rsa_key,
            leaf.clone(),
            Hash::Sha256,
            SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
        ))
        .add_signer(SignerSpec::new(
            ec_key,
            ec.clone(),
            Hash::Sha256,
            SignatureAlgorithm::Ecdsa(Hash::Sha256),
        ));
    let signed = builder.build(&mut rng).expect("build multi-signer");
    assert_eq!(signed.signer_infos.len(), 2);
    assert_eq!(signed.certificates.len(), 2);
    signed.verify(None).expect("both signatures verify");
    assert_eq!(signed.content(None).expect("content"), payload.as_slice());

    // The parsed object sees two signers and both verify.
    let der = signed.to_content_info().encode();
    let parsed = Pkcs7::parse(&der).expect("parse pkcs7");
    let Pkcs7::SignedData(parsed) = parsed else {
        panic!("not signed data");
    };
    parsed.verify(None).expect("parsed multi-signer verifies");
    assert_eq!(parsed.signer_infos.len(), 2);

    // Tampering with the content fails verification.
    let mut tampered = der.clone();
    let position = tampered
        .windows(payload.len())
        .position(|window| window == payload.as_slice())
        .expect("content in DER");
    tampered[position] ^= 1;
    let parsed = Pkcs7::parse(&tampered).expect("still parses");
    let Pkcs7::SignedData(parsed) = parsed else {
        panic!("not signed data");
    };
    assert!(parsed.verify(None).is_err());

    // OpenSSL verifies the crown-built multi-signer CMS.
    let path = std::env::temp_dir().join("crown-multisign.der");
    std::fs::write(&path, &der).expect("write");
    if let Some(output) = openssl(&[
        "cms",
        "-verify",
        "-inform",
        "DER",
        "-in",
        path.to_str().unwrap(),
        "-noverify",
        "-binary",
        "-out",
        "/dev/null",
    ]) {
        assert!(
            output.status.success(),
            "openssl cms -verify failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn detached_multi_signer() {
    let mut rng = TestRng(0xd);
    let payload = read("payload.txt");
    let leaf = certificate("leaf.pem");
    let ec = certificate("ec.pem");
    let rsa_key = private_key("rsa_pkcs8.pem", None);
    let ec_key = private_key("ec_pkcs8.pem", None);
    let signed = SignedDataMultiBuilder::detached(payload.clone())
        .add_signer(SignerSpec::new(
            rsa_key,
            leaf,
            Hash::Sha256,
            SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
        ))
        .add_signer(SignerSpec::new(
            ec_key,
            ec,
            Hash::Sha256,
            SignatureAlgorithm::Ecdsa(Hash::Sha256),
        ))
        .build(&mut rng)
        .expect("build detached");
    assert!(signed.encap_content_info.content.is_none());
    signed
        .verify(Some(&payload))
        .expect("detached signatures verify");
    assert!(signed.verify(Some(b"other")).is_err());

    // Extra signed attributes are carried and signed.
    let leaf = certificate("leaf.pem");
    let rsa_key = private_key("rsa_pkcs8.pem", None);
    let mut spec = SignerSpec::new(
        rsa_key,
        leaf,
        Hash::Sha512,
        SignatureAlgorithm::RsaPkcs1v15(Hash::Sha512),
    );
    spec.extra_attributes
        .push(crown::x509::attribute::friendly_name("multi"));
    let signed = SignedDataMultiBuilder::new(payload.clone())
        .add_signer(spec)
        .build(&mut rng)
        .expect("build with extra attributes");
    let signer = &signed.signer_infos[0];
    assert!(signer
        .signed_attrs
        .as_ref()
        .expect("attrs")
        .iter()
        .any(|attribute| attribute
            .oid
            .matches(crown::asn1::oid::OID_PKCS9_FRIENDLY_NAME)));
    let der = signed.to_content_info().encode();
    let Pkcs7::SignedData(parsed) = Pkcs7::parse(&der).expect("parse") else {
        panic!("not signed data");
    };
    parsed
        .verify(None)
        .expect("extra attribute signature verifies");
}
