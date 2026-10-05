//! CMP integration tests: OpenSSL-generated fixtures and crown-built
//! messages.
//!
//! Every fixture under `tests/data/pki/cmp_*` was produced by the vendored
//! OpenSSL CLI; see the comments for the exact commands. Password-protected
//! fixtures are MAC-verified, the signature-protected fixture is verified
//! against its signer in `extraCerts`, and CRMF POPO signatures are checked.
//! The reverse direction builds messages with crown and has OpenSSL parse
//! them (and validate/enroll one through its mock CMP server) when the
//! binary exists (`CROWN_OPENSSL` overrides the default path).

use crown::asn1::oid;
use crown::cmp::{
    pki_status_name, CertConfirmContent, CertStatus, ErrorMsgContent, InfoTypeAndValue, PkiBody,
    PkiHeader, PkiMessage, PkiStatusInfo, PollRep, PollRepContent, PollReq, PollReqContent,
    RevReqContent, PKI_STATUS_ACCEPTED, PKI_STATUS_GRANTED_WITH_MODS,
    PKI_STATUS_KEY_UPDATE_WARNING, PKI_STATUS_REJECTION, PKI_STATUS_REVOCATION_NOTIFICATION,
    PKI_STATUS_REVOCATION_WARNING, PKI_STATUS_WAITING, PVNO_CMP2000, PVNO_CMP2021,
};
use crown::crmf::{
    CertReqMessages, CertReqMsg, CertTemplate, OptionalValidity, PbmParameter, ProofOfPossession,
    OID_ID_PASSWORD_BASED_MAC,
};
use crown::rng::Rng;
use crown::x509::algorithm::{Hash, SignatureAlgorithm};
use crown::x509::cert::Certificate;
use crown::x509::extensions::GeneralName;
use crown::x509::keys::{PrivateKey, PrivateKeyInfo};
use crown::x509::name::Name;

const BASE: &str = "tests/data/pki/";

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{BASE}{name}")).unwrap_or_else(|err| panic!("read {name}: {err}"))
}

fn certificate(name: &str) -> Certificate {
    Certificate::from_pem(&String::from_utf8(read(name)).unwrap())
        .unwrap_or_else(|err| panic!("parse {name}: {err:?}"))
}

fn private_key(name: &str) -> PrivateKey {
    let der = crown::asn1::pem::parse_first(&String::from_utf8(read(name)).unwrap())
        .unwrap_or_else(|err| panic!("pem {name}: {err:?}"))
        .data;
    PrivateKeyInfo::parse(&der)
        .unwrap_or_else(|err| panic!("pkcs8 {name}: {err:?}"))
        .decode()
        .unwrap_or_else(|err| panic!("decode {name}: {err:?}"))
}

/// A small deterministic generator so built messages are reproducible.
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

fn directory(cn: &str) -> GeneralName {
    GeneralName::DirectoryName(Name::from_common_name(cn))
}

// ---------------------------------------------------------------------------
// OpenSSL fixtures
// ---------------------------------------------------------------------------

/// Parse and MAC-verify the password-protected request fixtures.
///
/// Generation commands (OpenSSL 3.5):
/// ```text
/// openssl cmp -cmd ir     -newkey ir.key -subject /CN=Test      -recipient /CN=Test\ CA \
///     -secret pass:test -ref clientref -srv_secret pass:test -srv_ref srvref \
///     -use_mock_srv -certout enrolled.pem -reqout cmp_ir_secret.der
/// openssl cmp -cmd cr     -newkey cr.key -subject /CN=TestCr    ...
/// openssl cmp -cmd p10cr  -csr p10.csr ...
/// openssl cmp -cmd rr     -oldcert client.pem -revreason 1 ...
/// openssl cmp -cmd genm   -infotype caCerts ...
/// ```
#[test]
fn openssl_secret_fixtures_parse_and_verify() {
    let fixtures = [
        ("cmp_ir_secret.der", "ir", "Test"),
        ("cmp_cr_secret.der", "cr", "TestCr"),
        ("cmp_p10cr_secret.der", "p10cr", "P10 Test"),
        ("cmp_rr_secret.der", "rr", "CMP Client"),
        ("cmp_genm_secret.der", "genm", ""),
    ];
    let mut checked = 0;
    for (name, kind, common_name) in fixtures {
        let der = read(name);
        let message = PkiMessage::parse(&der).unwrap_or_else(|err| panic!("{name}: {err:?}"));
        assert_eq!(message.encode(), der, "{name}: byte-exact re-encode");
        assert_eq!(message.header.pvno, PVNO_CMP2000, "{name}: pvno");
        assert_eq!(message.body.name(), kind, "{name}: body kind");
        assert!(message.header.message_time.is_some(), "{name}: messageTime");
        assert!(
            message.header.transaction_id.is_some(),
            "{name}: transactionID"
        );
        assert!(message.header.sender_nonce.is_some(), "{name}: senderNonce");
        match &message.header.sender {
            GeneralName::DirectoryName(name) => {
                if common_name.is_empty() {
                    assert!(name.rdns.is_empty(), "{name}: expected NULL-DN");
                } else {
                    assert_eq!(name.common_name().as_deref(), Some(common_name), "{name}");
                }
            }
            other => panic!("{name}: unexpected sender {other:?}"),
        }

        let protection = message
            .protection
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: no protection"));
        assert!(
            protection.alg_id.oid.matches(OID_ID_PASSWORD_BASED_MAC),
            "{name}: not id-PasswordBasedMac"
        );
        let parameters = PbmParameter::parse(protection.alg_id.parameters.as_deref().unwrap())
            .unwrap_or_else(|err| panic!("{name}: PBMParameter: {err:?}"));
        assert_eq!(parameters.salt.len(), 16, "{name}: salt");
        assert_eq!(parameters.iteration_count, 500, "{name}: iterations");
        assert!(parameters.owf.oid.matches(oid::OID_SHA256), "{name}: owf");
        assert!(
            parameters.mac.oid.matches(&[1, 3, 6, 1, 5, 5, 8, 1, 2]),
            "{name}: mac {}",
            parameters.mac.oid
        );
        assert!(message.verify_password(b"test").unwrap(), "{name}: MAC");
        assert!(
            !message.verify_password(b"wrong").unwrap(),
            "{name}: bad MAC"
        );

        match &message.body {
            PkiBody::Ir(messages) | PkiBody::Cr(messages) | PkiBody::Kur(messages) => {
                assert_eq!(messages.messages.len(), 1, "{name}: one CertReqMsg");
                assert!(
                    messages.messages[0].popo.is_some(),
                    "{name}: missing signature POPO"
                );
                assert_eq!(
                    messages.messages[0].verify_popo().unwrap(),
                    Some(true),
                    "{name}: POPO signature"
                );
            }
            PkiBody::P10Cr(request) => {
                assert!(
                    request.verify_signature().unwrap(),
                    "{name}: PKCS#10 signature"
                );
            }
            PkiBody::Rr(content) => {
                assert_eq!(content.details.len(), 1, "{name}: RevDetails count");
                assert!(
                    !content.details[0].crl_entry_details.is_empty(),
                    "{name}: crlEntryDetails"
                );
            }
            PkiBody::Genm(content) => {
                assert!(
                    content
                        .values
                        .iter()
                        .any(|value| value.info_type.matches(&[1, 3, 6, 1, 5, 5, 7, 4, 17])),
                    "{name}: id-it-caCerts"
                );
            }
            other => panic!("{name}: unexpected body {other:?}"),
        }
        checked += 1;
    }
    assert!(checked >= 5, "only {checked} secret fixtures verified");
}

/// The signature-protected IR fixture generated with
/// `openssl cmp -cmd ir ... -cert client.pem -key client.key
/// -extracerts client.pem ...`, which signs `SEQUENCE { header, body }` with
/// the client certificate's key and carries the signer in `extraCerts`.
#[test]
fn openssl_signed_fixture_verifies() {
    let der = read("cmp_ir_signed.der");
    let message = PkiMessage::parse(&der).expect("parse signed IR");
    assert_eq!(message.encode(), der, "byte-exact re-encode");
    assert_eq!(message.header.pvno, PVNO_CMP2000);
    assert_eq!(message.body.name(), "ir");
    assert_eq!(message.extra_certs.len(), 1, "extraCerts");
    assert_eq!(
        message.extra_certs[0].subject().common_name().as_deref(),
        Some("CMP Client")
    );
    let protection = message.protection.as_ref().expect("protection");
    assert!(
        protection.alg_id.oid.matches(oid::OID_SHA256_WITH_RSA),
        "expected sha256WithRSAEncryption protection"
    );
    assert!(message.verify_signature().unwrap(), "signature protection");
    assert!(!message.verify_password(b"test").unwrap());

    // The CRMF POPO inside the body is a signature over the CertRequest.
    if let PkiBody::Ir(messages) = &message.body {
        assert_eq!(messages.messages[0].verify_popo().unwrap(), Some(true));
    } else {
        panic!("expected ir body");
    }

    // Modifying the body must invalidate the signature.
    let mut tampered = message.clone();
    if let PkiBody::Ir(messages) = &mut tampered.body {
        messages.messages[0].cert_req.cert_template.subject =
            Some(Name::from_common_name("Mallory"));
    }
    let tampered = PkiMessage::parse(&tampered.encode()).unwrap();
    assert!(!tampered.verify_signature().unwrap(), "tampered signature");
}

/// Modifying a password-protected fixture's body must fail the MAC.
#[test]
fn tampered_password_fixture_is_rejected() {
    let der = read("cmp_ir_secret.der");
    let message = PkiMessage::parse(&der).unwrap();
    let mut tampered = message.clone();
    if let PkiBody::Ir(messages) = &mut tampered.body {
        messages.messages[0].cert_req.cert_template.subject =
            Some(Name::from_common_name("Mallory"));
    }
    let tampered = PkiMessage::parse(&tampered.encode()).unwrap();
    assert!(!tampered.verify_password(b"test").unwrap());
}

// ---------------------------------------------------------------------------
// Crown-built messages
// ---------------------------------------------------------------------------

fn test_header() -> PkiHeader {
    let mut header = PkiHeader::new(directory("Crown Client"), directory("Test CA"));
    header.message_time =
        Some(crown::asn1::time::Asn1Time::new(2026, 1, 2, 3, 4, 5, false).unwrap());
    header.sender_kid = Some(b"crown-ref".to_vec());
    header.transaction_id = Some(vec![0x11; 16]);
    header.sender_nonce = Some(vec![0x22; 16]);
    header
}

fn crown_ir() -> PkiMessage {
    let key = private_key("rsa_pkcs8.pem");
    let public = key.public_key().unwrap();
    let mut request = CertReqMsg::for_key_identifier(
        &public,
        Some(Name::from_common_name("Test CA")),
        Name::from_common_name("Crown Interop"),
    )
    .unwrap();
    request
        .sign_popo(
            &key,
            SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
            &mut TestRng(0x5eed),
        )
        .unwrap();
    PkiMessage::new(
        test_header(),
        PkiBody::Ir(CertReqMessages::new(vec![request])),
    )
}

#[test]
fn crown_built_ir_round_trips() {
    let mut message = crown_ir();
    message
        .protect_password(b"test", &mut TestRng(0xabcd))
        .unwrap();
    let der = message.encode();
    let parsed = PkiMessage::parse(&der).expect("parse crown IR");
    assert_eq!(parsed, message);
    assert_eq!(parsed.encode(), der);
    assert!(parsed.verify_password(b"test").unwrap());
    assert!(!parsed.verify_password(b"hunter2").unwrap());
    assert_eq!(parsed.header.pvno, PVNO_CMP2000);

    // Re-protecting with a signature yields a message that verifies against
    // the embedded certificate.
    let key = private_key("rsa_pkcs8.pem");
    let cert = certificate("leaf.pem");
    let mut signed = crown_ir();
    signed
        .protect_signature(
            &cert,
            &key,
            SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
            &mut TestRng(9),
        )
        .unwrap();
    assert_eq!(signed.extra_certs.len(), 1);
    let signed = PkiMessage::parse(&signed.encode()).unwrap();
    assert!(signed.verify_signature().unwrap());
}

/// CRMF-only end-to-end: build `CertReqMessages` with a signature POPO,
/// round trip it, and verify the POPO.
#[test]
fn crmf_signature_popo_round_trip() {
    let key = private_key("rsa_pkcs8.pem");
    let public = key.public_key().unwrap();
    let mut template = CertTemplate::new();
    template.subject = Some(Name::from_common_name("CRMF Only"));
    template.public_key =
        Some(crown::x509::keys::SubjectPublicKeyInfo::from_public_key(&public).unwrap());
    template.validity = OptionalValidity::new()
        .with_not_before(crown::asn1::time::Asn1Time::new(2026, 1, 1, 0, 0, 0, false).unwrap());
    let mut request = CertReqMsg::new(crown::crmf::CertRequest::new(vec![0], template));
    request
        .sign_popo(
            &key,
            SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
            &mut TestRng(0x1234),
        )
        .unwrap();
    assert!(matches!(
        request.popo,
        Some(ProofOfPossession::Signature(_))
    ));

    let messages = CertReqMessages::new(vec![request]);
    let der = messages.encode();
    let parsed = CertReqMessages::parse(&der).expect("parse CertReqMessages");
    assert_eq!(parsed.messages.len(), 1);
    assert_eq!(parsed.encode(), der);
    assert_eq!(parsed.messages[0].verify_popo().unwrap(), Some(true));

    let mut tampered = parsed;
    tampered.messages[0].cert_req.cert_template.subject = Some(Name::from_common_name("Mallory"));
    assert_eq!(tampered.messages[0].verify_popo().unwrap(), Some(false));
}

#[test]
fn status_names_and_confirm_content() {
    assert_eq!(pki_status_name(PKI_STATUS_ACCEPTED), "accepted");
    assert_eq!(
        pki_status_name(PKI_STATUS_GRANTED_WITH_MODS),
        "grantedWithMods"
    );
    assert_eq!(pki_status_name(PKI_STATUS_REJECTION), "rejection");
    assert_eq!(pki_status_name(PKI_STATUS_WAITING), "waiting");
    assert_eq!(
        pki_status_name(PKI_STATUS_REVOCATION_WARNING),
        "revocationWarning"
    );
    assert_eq!(
        pki_status_name(PKI_STATUS_REVOCATION_NOTIFICATION),
        "revocationNotification"
    );
    assert_eq!(
        pki_status_name(PKI_STATUS_KEY_UPDATE_WARNING),
        "keyUpdateWarning"
    );
    assert_eq!(pki_status_name(99), "unknown");
    assert_eq!(PVNO_CMP2021, 3);

    let content = CertConfirmContent {
        statuses: vec![CertStatus::new(vec![0xab; 32], Vec::new())],
    };
    let message = PkiMessage::new(test_header(), PkiBody::CertConf(content));
    let der = message.encode();
    let parsed = PkiMessage::parse(&der).unwrap();
    assert_eq!(parsed, message);

    // InfoTypeAndValue helpers survive a round trip through the header.
    let mut header = test_header();
    header.set_general_info(InfoTypeAndValue::implicit_confirm());
    header.set_general_info(InfoTypeAndValue::cert_profile(&["a", "b"]));
    let message = PkiMessage::new(header, PkiBody::Genp(crown::cmp::GenRepContent::default()));
    let der = message.encode();
    let parsed = PkiMessage::parse(&der).unwrap();
    assert_eq!(parsed, message);
    assert!(parsed.header.implicit_confirm());
    assert_eq!(parsed.header.cert_profiles().unwrap(), vec!["a", "b"]);

    // Body variants that are not exercised by the fixtures still round trip.
    for body in [
        PkiBody::Rr(RevReqContent::default()),
        PkiBody::Genp(crown::cmp::GenRepContent::default()),
        PkiBody::PollReq(PollReqContent {
            requests: vec![PollReq::new(Vec::new())],
        }),
        PkiBody::PollRep(PollRepContent {
            responses: vec![PollRep::new(vec![1], 60)],
        }),
        PkiBody::Error(ErrorMsgContent::new(PKI_STATUS_REJECTION)),
        PkiBody::Pkiconf,
        PkiBody::Other {
            tag: 1,
            value: crown::asn1::der::sequence(&crown::asn1::der::null()),
        },
    ] {
        let message = PkiMessage::new(test_header(), body);
        let der = message.encode();
        let parsed = PkiMessage::parse(&der).expect("body round trip");
        assert_eq!(parsed, message);
    }
}

// ---------------------------------------------------------------------------
// OpenSSL CLI interop (skipped when the binary is absent)
// ---------------------------------------------------------------------------

struct OpenSsl {
    binary: String,
    library_path: String,
}

fn openssl() -> Option<OpenSsl> {
    if let Ok(binary) = std::env::var("CROWN_OPENSSL") {
        return Some(OpenSsl {
            binary,
            library_path: std::env::var("CROWN_OPENSSL_LIB").unwrap_or_default(),
        });
    }
    let binary = "/home/loongtao/crown-ref/openssl/apps/openssl".to_string();
    if std::path::Path::new(&binary).exists() {
        Some(OpenSsl {
            binary,
            library_path: "/home/loongtao/crown-ref/openssl".to_string(),
        })
    } else {
        None
    }
}

impl OpenSsl {
    fn run(&self, args: &[&str]) -> std::process::Output {
        std::process::Command::new(&self.binary)
            .args(args)
            .env("LD_LIBRARY_PATH", &self.library_path)
            .output()
            .unwrap_or_else(|err| panic!("run openssl: {err}"))
    }

    /// Whether OpenSSL can decode the DER structure at all.
    fn asn1parse(&self, tag: &str, der: &[u8]) -> std::process::Output {
        let path = temp_file(&format!("{tag}.der"));
        std::fs::write(&path, der).unwrap();
        let output = self.run(&["asn1parse", "-inform", "DER", "-in", path.to_str().unwrap()]);
        let _ = std::fs::remove_file(&path);
        output
    }
}

fn temp_file(name: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("crown_cmp_{}_{name}", std::process::id()));
    path
}

fn assert_openssl_ok(output: &std::process::Output, what: &str) {
    assert!(
        output.status.success(),
        "{what}: openssl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Build an IR (with signature POPO), an error and a pkiconf message with
/// crown and assert OpenSSL parses them. The IR is additionally fed to
/// OpenSSL's mock CMP server, which verifies crown's password protection and
/// CRMF POPO and completes an enrollment.
#[test]
fn openssl_parses_crown_built_messages() {
    let Some(openssl) = openssl() else {
        eprintln!(
            "skipping: set CROWN_OPENSSL to the OpenSSL binary to run interop; \
             manual: openssl asn1parse -inform DER -in crown_cmp_ir.der \
             and openssl cmp -reqin crown_cmp_ir.der -ref crown-ref -secret pass:test \
             -srv_secret pass:test -srv_ref crown-ref -use_mock_srv \
             -rsp_cert leaf.pem -rsp_key rsa_pkcs8.pem -certout out.pem"
        );
        return;
    };

    let mut ir = crown_ir();
    ir.protect_password(b"test", &mut TestRng(0x1111)).unwrap();

    let mut error = PkiMessage::new(
        test_header(),
        PkiBody::Error(ErrorMsgContent {
            pki_status_info: {
                let mut status = PkiStatusInfo::new(PKI_STATUS_REJECTION);
                status.status_string.push("bad request".into());
                status.fail_info = Some(vec![0b0000_0100]); // badDataFormat (bit 5)
                status
            },
            error_code: Some(5),
            error_details: vec!["crown error".into()],
        }),
    );
    error
        .protect_password(b"test", &mut TestRng(0x2222))
        .unwrap();

    let mut pkiconf = PkiMessage::new(test_header(), PkiBody::Pkiconf);
    pkiconf
        .protect_password(b"test", &mut TestRng(0x3333))
        .unwrap();

    for (tag, message) in [("ir", &ir), ("error", &error), ("pkiconf", &pkiconf)] {
        let output = openssl.asn1parse(&format!("crown_{tag}"), &message.encode());
        assert_openssl_ok(&output, &format!("asn1parse crown {tag}"));
    }

    // Full enrollment through the mock server: it validates the MAC of the
    // IR and the POPO signature, then issues leaf.pem's certificate (whose
    // key matches the requested key, so the transaction completes).
    let input = temp_file("crown_ir.der");
    let certout = temp_file("crown_ir_cert.pem");
    let _ = std::fs::remove_file(&certout);
    std::fs::write(&input, ir.encode()).unwrap();
    let rsp_cert = format!("{BASE}leaf.pem");
    let rsp_key = format!("{BASE}rsa_pkcs8.pem");
    let output = openssl.run(&[
        "cmp",
        "-cmd",
        "ir",
        "-reqin",
        input.to_str().unwrap(),
        "-newkey",
        &rsp_key,
        "-ref",
        "crown-ref",
        "-secret",
        "pass:test",
        "-srv_secret",
        "pass:test",
        "-srv_ref",
        "crown-ref",
        "-use_mock_srv",
        "-rsp_cert",
        &rsp_cert,
        "-rsp_key",
        &rsp_key,
        "-certout",
        certout.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        output.status.success(),
        "openssl mock enrollment failed: {stderr}\n{stdout}"
    );
    // The mock server only writes `-certout` after it has verified the
    // message protection and POPO and completed the transaction.
    assert!(
        certout.exists(),
        "no certificate written: stderr={stderr} stdout={stdout}"
    );

    // Negative: a server that does not share the password must reject the
    // message and must not issue a certificate.
    let wrong_out = temp_file("crown_ir_wrong_cert.pem");
    let _ = std::fs::remove_file(&wrong_out);
    let rejected = openssl.run(&[
        "cmp",
        "-cmd",
        "ir",
        "-reqin",
        input.to_str().unwrap(),
        "-newkey",
        &rsp_key,
        "-ref",
        "crown-ref",
        "-secret",
        "pass:test",
        "-srv_secret",
        "pass:wrong",
        "-srv_ref",
        "crown-ref",
        "-use_mock_srv",
        "-rsp_cert",
        &rsp_cert,
        "-rsp_key",
        &rsp_key,
        "-certout",
        wrong_out.to_str().unwrap(),
    ]);
    assert!(
        !rejected.status.success(),
        "openssl accepted a wrong password: {}",
        String::from_utf8_lossy(&rejected.stdout)
    );
    assert!(!wrong_out.exists(), "certificate issued despite bad MAC");
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&certout);
    let _ = std::fs::remove_file(&wrong_out);
}
