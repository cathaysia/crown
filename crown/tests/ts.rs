//! RFC 3161 timestamping integration tests.
//!
//! Fixtures under `tests/data/pki/ts_*` were produced with the vendored
//! OpenSSL 3.5.8 CLI (see the repository history for the exact commands):
//!
//! ```text
//! openssl req -x509 -newkey rsa:2048 -keyout ts_ca.key -out ts_ca.pem \
//!     -days 3650 -nodes -subj "/CN=crown TS Test CA" \
//!     -addext "basicConstraints=critical,CA:TRUE" \
//!     -addext "keyUsage=critical,keyCertSign,cRLSign"
//! openssl req -new -newkey rsa:2048 -keyout tsa.key -out tsa.csr \
//!     -nodes -subj "/CN=crown TSA"
//! openssl x509 -req -in tsa.csr -CA ts_ca.pem -CAkey ts_ca.key \
//!     -CAcreateserial -out tsa.pem -days 3650 -extfile ext.cnf
//! openssl ts -query -data data.txt -sha256 -cert -out ts_query_sha256.der
//! openssl ts -reply -config tsa.cnf -queryfile ts_query_sha256.der \
//!     -inkey tsa.key -signer tsa.pem -chain ts_ca.pem -out ts_response_sha256.der
//! ```
//!
//! The reverse direction runs the OpenSSL `ts` command over crown-built
//! artifacts when the binary exists (`CROWN_OPENSSL` overrides the default
//! path, `CROWN_OPENSSL_LIB` the library path).

use crown::asn1::oid;
use crown::cms::ContentInfo;
use crown::pkcs7::SignedData;
use crown::rng::Rng;
use crown::ts::{
    Accuracy, MessageImprint, SigningCertificateV2, TimeStampReq, TimeStampResp, TimeStampSigner,
    OID_ID_AA_SIGNING_CERTIFICATE_V2, OID_ID_CT_TST_INFO, PKI_STATUS_GRANTED,
};
use crown::x509::algorithm::{Hash, SignatureAlgorithm};
use crown::x509::cert::Certificate;
use crown::x509::extensions::{
    BasicConstraints, ExtendedKeyUsage, Extension, GeneralName, KeyUsage,
};
use crown::x509::keys::{PrivateKey, PrivateKeyInfo};
use crown::x509::name::Name;

const BASE: &str = "tests/data/pki/";
const PAYLOAD: &[u8] = b"crown timestamp test payload\n";
const POLICY: &str = "1.2.3.4.1";

/// A small deterministic generator so the tests are reproducible.
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

fn sample_time() -> crown::asn1::time::Asn1Time {
    // `utc: true` makes the signingTime attribute a UTCTime, as OpenSSL emits.
    crown::asn1::time::Asn1Time::new(2026, 10, 5, 12, 30, 45, true).unwrap()
}

fn policy() -> crown::asn1::oid::ObjectIdentifier {
    crown::asn1::oid::ObjectIdentifier::from_dotted_string(POLICY).unwrap()
}

fn openssl_tsa_signer() -> TimeStampSigner {
    TimeStampSigner::new(
        certificate("ts_tsa.pem"),
        private_key("ts_tsa_key.pem"),
        vec![certificate("ts_ca.pem")],
        SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
    )
}

// ---------------------------------------------------------------------------
// OpenSSL fixtures: parse and verify
// ---------------------------------------------------------------------------

#[test]
fn openssl_queries_parse() {
    // (file, hash, certReq, has_nonce)
    let cases = [
        ("ts_query_sha256.der", Hash::Sha256, true, true),
        ("ts_query_sha512.der", Hash::Sha512, true, true),
        ("ts_query_sha1.der", Hash::Sha1, true, true),
        ("ts_query_sha256_noncefree.der", Hash::Sha256, true, false),
    ];
    let mut checked = 0;
    for (name, hash, cert_req, has_nonce) in cases {
        let der = read(name);
        let request = TimeStampReq::parse(&der).unwrap_or_else(|err| panic!("parse {name}: {err}"));
        assert_eq!(request.version, 1, "{name}: version");
        assert_eq!(
            request.message_imprint.hash().unwrap(),
            hash,
            "{name}: hash algorithm"
        );
        assert!(
            request.verify_message_imprint(PAYLOAD).unwrap(),
            "{name}: imprint"
        );
        assert!(
            !request.verify_message_imprint(b"tampered").unwrap(),
            "{name}: tampered imprint accepted"
        );
        assert_eq!(request.cert_req, cert_req, "{name}: certReq");
        assert_eq!(request.nonce.is_some(), has_nonce, "{name}: nonce");
        assert!(request.req_policy.is_none(), "{name}: reqPolicy");
        assert!(request.extensions.is_none(), "{name}: extensions");
        // Re-encoding is byte-exact.
        assert_eq!(request.encode(), der, "{name}: re-encode");

        // The PEM form round-trips through the documented label.
        let pem = request.to_pem();
        assert!(pem.starts_with("-----BEGIN TIME STAMP REQUEST-----"));
        assert_eq!(
            TimeStampReq::from_pem(&pem).unwrap().encode(),
            der,
            "{name}: PEM round trip"
        );
        checked += 1;
    }
    assert!(checked >= 4, "only {checked} queries parsed");
}

#[test]
fn openssl_responses_verify() {
    let tsa = certificate("ts_tsa.pem");
    let cases = [
        (
            "ts_response_sha256.der",
            "ts_query_sha256.der",
            Hash::Sha256,
        ),
        (
            "ts_response_sha512.der",
            "ts_query_sha512.der",
            Hash::Sha512,
        ),
        ("ts_response_sha1.der", "ts_query_sha1.der", Hash::Sha1),
        (
            "ts_response_sha256_noncefree.der",
            "ts_query_sha256_noncefree.der",
            Hash::Sha256,
        ),
    ];
    let mut checked = 0;
    for (response_name, query_name, hash) in cases {
        let der = read(response_name);
        let response =
            TimeStampResp::parse(&der).unwrap_or_else(|err| panic!("parse {response_name}: {err}"));
        assert!(response.is_granted(), "{response_name}: not granted");
        assert_eq!(
            response.status.status, PKI_STATUS_GRANTED,
            "{response_name}: status"
        );
        assert!(
            response.status.status_string.is_empty(),
            "{response_name}: statusString"
        );
        assert!(response.status.fail_info.is_none());
        assert_eq!(response.encode(), der, "{response_name}: re-encode");
        assert!(response
            .to_pem()
            .starts_with("-----BEGIN TIME STAMP RESPONSE-----"));
        assert_eq!(
            TimeStampResp::from_pem(&response.to_pem())
                .unwrap()
                .encode(),
            der
        );

        let info = response
            .verify(&tsa)
            .unwrap_or_else(|err| panic!("verify {response_name}: {err}"));
        assert_eq!(response.basic().unwrap(), info, "{response_name}: basic()");

        let request_der = read(query_name);
        let request = TimeStampReq::parse(&request_der).unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.policy.to_dotted_string(), POLICY);
        assert_eq!(
            info.message_imprint, request.message_imprint,
            "{response_name}: imprint echo"
        );
        assert_eq!(info.nonce, request.nonce, "{response_name}: nonce echo");
        assert_eq!(info.message_imprint.hash().unwrap(), hash);
        assert!(info.message_imprint.matches(PAYLOAD).unwrap());
        assert!(!info.serial_number.is_empty(), "{response_name}: serial");
        assert!(info.gen_time.year >= 2026, "{response_name}: genTime");
        match &info.tsa {
            Some(GeneralName::DirectoryName(name)) => {
                assert_eq!(
                    name.common_name().as_deref(),
                    Some("crown TSA"),
                    "{response_name}: TSA name"
                );
            }
            other => panic!("{response_name}: unexpected TSA name {other:?}"),
        }
        response
            .verify_request(&tsa, &request)
            .unwrap_or_else(|err| panic!("verify_request {response_name}: {err}"));

        // Tampered message imprint must not verify against the response.
        let mut tampered = request.clone();
        tampered.message_imprint.hashed_message[0] ^= 1;
        assert!(
            response.verify_request(&tsa, &tampered).is_err(),
            "{response_name}: tampered imprint accepted"
        );
        // A mismatching nonce must not verify either.
        if request.nonce.is_some() {
            let mut wrong_nonce = request.clone();
            wrong_nonce.nonce = Some(vec![0xff; 8]);
            assert!(
                response.verify_request(&tsa, &wrong_nonce).is_err(),
                "{response_name}: wrong nonce accepted"
            );
        }
        // Tampering with the token signature must fail.
        let token = response.token().unwrap();
        let mut signed_data = SignedData::parse(&token.content).unwrap();
        signed_data.signer_infos[0].signature[0] ^= 1;
        let broken = TimeStampResp {
            status: response.status.clone(),
            time_stamp_token: Some(signed_data.to_content_info()),
        };
        assert!(
            broken.verify(&tsa).is_err(),
            "{response_name}: tampered signature accepted"
        );
        checked += 1;
    }
    assert!(checked >= 4, "only {checked} responses verified");

    // The accuracy values configured for the fixture TSA.
    let info = TimeStampResp::parse(&read("ts_response_sha256.der"))
        .unwrap()
        .basic()
        .unwrap();
    let accuracy = info.accuracy.expect("accuracy present");
    assert_eq!(accuracy.seconds, Some(1));
    assert_eq!(accuracy.millis, Some(500));
    assert_eq!(accuracy.micros, Some(100));
    assert!(info.ordering, "ordering flag");
    assert_eq!(info.nonce.as_ref().map(Vec::len), Some(8));
}

#[test]
fn openssl_token_out_fixture_parses() {
    let der = read("ts_response_sha256_token.der");
    let token = ContentInfo::parse(&der).unwrap();
    assert!(token.is_signed_data(), "token is not id-signedData");
    let signed_data = SignedData::parse(&token.content).unwrap();
    assert_eq!(signed_data.version, 3, "SignedData version");
    assert!(signed_data
        .encap_content_info
        .content_type
        .matches(OID_ID_CT_TST_INFO));
    assert!(!signed_data.certificates.is_empty(), "no embedded certs");
    let info =
        crown::ts::TstInfo::parse(signed_data.encap_content_info.content.as_deref().unwrap())
            .unwrap();
    assert_eq!(info.policy.to_dotted_string(), POLICY);

    // The extracted token can be verified inside a TimeStampResp wrapper.
    let tsa = certificate("ts_tsa.pem");
    let response = TimeStampResp {
        status: crown::ts::PkiStatusInfo::granted(),
        time_stamp_token: Some(token),
    };
    let request = TimeStampReq::parse(&read("ts_query_sha256.der")).unwrap();
    let token_der = response.token().unwrap().encode();
    let info = response.verify(&tsa).unwrap();
    assert_eq!(info.message_imprint, request.message_imprint);
    assert_eq!(info.nonce, request.nonce);
    assert_eq!(token_der, der, "token-out fixture re-encode");
}

// ---------------------------------------------------------------------------
// Crown-built replies
// ---------------------------------------------------------------------------

#[test]
fn crown_rsa_reply_round_trip() {
    let rng = &mut TestRng(1);
    let tsa = certificate("ts_tsa.pem");
    let signer = openssl_tsa_signer().signing_time(sample_time());
    let mut request = TimeStampReq::for_data(PAYLOAD, Hash::Sha256, true).unwrap();
    request.nonce = Some(vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);

    let response = signer
        .reply(
            &request,
            policy(),
            &[0x0b, 0xad],
            sample_time(),
            Some(Accuracy {
                seconds: Some(1),
                millis: Some(500),
                micros: Some(100),
            }),
            rng,
        )
        .unwrap();
    assert!(response.is_granted());

    // Both the local verifier and the request-aware variant accept it.
    let info = response.verify(&tsa).unwrap();
    assert_eq!(info.policy.to_dotted_string(), POLICY);
    assert_eq!(info.serial_number, vec![0x0b, 0xad]);
    assert_eq!(info.message_imprint, request.message_imprint);
    assert_eq!(info.nonce, request.nonce);
    response.verify_request(&tsa, &request).unwrap();

    // The token is version 3 CMS with the TSTInfo content type and the
    // signingCertificateV2 attribute, and embeds the signer plus the chain.
    let token = response.token().unwrap();
    assert!(token.is_signed_data());
    let signed_data = SignedData::parse(&token.content).unwrap();
    assert_eq!(signed_data.version, 3);
    assert_eq!(signed_data.certificates.len(), 2);
    assert_eq!(
        signed_data.certificates[0].encode(),
        tsa.encode(),
        "signer certificate is embedded first"
    );
    let signer_info = &signed_data.signer_infos[0];
    assert_eq!(signer_info.version, 1);
    assert!(signer_info
        .signature_algorithm
        .oid
        .matches(oid::OID_RSA_ENCRYPTION));
    let attributes = signer_info.signed_attrs.as_ref().unwrap();
    let attribute = attributes
        .iter()
        .find(|attribute| attribute.oid.matches(OID_ID_AA_SIGNING_CERTIFICATE_V2))
        .expect("signingCertificateV2 attribute");
    let signing = SigningCertificateV2::from_attribute(attribute).unwrap();
    assert!(signing.matches_certificate(&tsa).unwrap());
    assert!(attributes
        .iter()
        .any(|attribute| attribute.oid.matches(oid::OID_PKCS9_SIGNING_TIME)));

    // DER round trip is exact, and PEM round-trips too.
    let der = response.encode();
    let parsed = TimeStampResp::parse(&der).unwrap();
    assert_eq!(parsed.encode(), der);
    assert_eq!(
        TimeStampResp::from_pem(&response.to_pem())
            .unwrap()
            .encode(),
        der
    );

    // Negative: a tampered imprint or nonce must be rejected.
    let mut tampered = request.clone();
    tampered.message_imprint.hashed_message[0] ^= 1;
    assert!(parsed.verify_request(&tsa, &tampered).is_err());
    let mut wrong_nonce = request;
    wrong_nonce.nonce = Some(vec![0; 8]);
    assert!(parsed.verify_request(&tsa, &wrong_nonce).is_err());
}

#[test]
fn verification_falls_back_to_supplied_certificate() {
    let rng = &mut TestRng(4);
    let signer = openssl_tsa_signer();
    let request = TimeStampReq::for_data(PAYLOAD, Hash::Sha256, true).unwrap();
    let response = signer
        .reply(&request, policy(), &[0x01], sample_time(), None, rng)
        .unwrap();

    // Strip the embedded certificates: verification then has to use the
    // caller-supplied TSA certificate.
    let token = response.token().unwrap();
    let mut signed_data = SignedData::parse(&token.content).unwrap();
    signed_data.certificates.clear();
    let stripped = TimeStampResp {
        status: response.status.clone(),
        time_stamp_token: Some(signed_data.to_content_info()),
    };
    let info = stripped.verify(&certificate("ts_tsa.pem")).unwrap();
    assert_eq!(info.message_imprint, request.message_imprint);
    stripped
        .verify_request(&certificate("ts_tsa.pem"), &request)
        .unwrap();
    // A certificate without the timeStamping EKU must be rejected.
    assert!(stripped.verify(&certificate("ts_tsa_no_eku.pem")).is_err());
}

#[test]
fn crown_ecdsa_reply_round_trip() {
    let rng = &mut TestRng(2);
    let key = private_key("ec_pkcs8.pem");
    let algorithm = SignatureAlgorithm::Ecdsa(Hash::Sha256);
    let extensions = vec![
        Extension::new(
            crown::asn1::oid::ObjectIdentifier::new(oid::OID_BASIC_CONSTRAINTS).unwrap(),
            false,
            BasicConstraints::default().encode(),
        ),
        Extension::new(
            crown::asn1::oid::ObjectIdentifier::new(oid::OID_KEY_USAGE).unwrap(),
            true,
            KeyUsage {
                digital_signature: true,
                ..Default::default()
            }
            .encode(),
        ),
        Extension::new(
            crown::asn1::oid::ObjectIdentifier::new(oid::OID_EXTENDED_KEY_USAGE).unwrap(),
            true,
            ExtendedKeyUsage {
                purposes: vec![
                    crown::asn1::oid::ObjectIdentifier::new(oid::OID_KP_TIME_STAMPING).unwrap(),
                ],
            }
            .encode(),
        ),
    ];
    let certificate = Certificate::self_signed(
        Name::from_common_name("crown EC TSA test"),
        algorithm,
        &key,
        crown::asn1::time::Asn1Time::new(2026, 1, 1, 0, 0, 0, true).unwrap(),
        crown::asn1::time::Asn1Time::new(2046, 1, 1, 0, 0, 0, true).unwrap(),
        extensions,
        rng,
    )
    .unwrap();
    let signer = TimeStampSigner::new(certificate.clone(), key, Vec::new(), algorithm);
    let request = TimeStampReq::for_data(PAYLOAD, Hash::Sha384, true).unwrap();
    let response = signer
        .reply(&request, policy(), &[0x01], sample_time(), None, rng)
        .unwrap();
    let info = response.verify(&certificate).unwrap();
    assert_eq!(info.message_imprint.hash().unwrap(), Hash::Sha384);
    response.verify_request(&certificate, &request).unwrap();
    // The ECDSA identifier uses the request's digest, not the configured one.
    assert_eq!(
        signed_data_signature_algorithm(&response),
        SignatureAlgorithm::Ecdsa(Hash::Sha384).to_identifier().oid,
    );
}

/// The first signer's CMS signatureAlgorithm OID.
fn signed_data_signature_algorithm(response: &TimeStampResp) -> oid::ObjectIdentifier {
    let token = response.token().unwrap();
    let signed_data = SignedData::parse(&token.content).unwrap();
    signed_data.signer_infos[0].signature_algorithm.oid.clone()
}

#[test]
fn missing_eku_is_rejected() {
    let rng = &mut TestRng(3);
    let no_eku = certificate("ts_tsa_no_eku.pem");
    let key = private_key("ts_tsa_key.pem");
    let signer = TimeStampSigner::new(
        no_eku.clone(),
        key,
        Vec::new(),
        SignatureAlgorithm::RsaPkcs1v15(Hash::Sha256),
    );
    let request = TimeStampReq::for_data(PAYLOAD, Hash::Sha256, true).unwrap();
    let response = signer
        .reply(&request, policy(), &[0x01], sample_time(), None, rng)
        .unwrap();
    // The embedded certificate has no timeStamping EKU.
    assert!(response.verify(&no_eku).is_err());
    // Even verifying against the real TSA certificate fails, because the
    // token's own embedded signer certificate is located first.
    assert!(response.verify(&certificate("ts_tsa.pem")).is_err());
    assert!(response.verify_request(&no_eku, &request).is_err());
}

#[test]
fn openssl_token_carries_signing_certificate_v2() {
    let tsa = certificate("ts_tsa.pem");
    let response = TimeStampResp::parse(&read("ts_response_sha256.der")).unwrap();
    let token = response.token().unwrap();
    let signed_data = SignedData::parse(&token.content).unwrap();
    let signer = &signed_data.signer_infos[0];
    let attribute = signer
        .signed_attrs
        .as_ref()
        .unwrap()
        .iter()
        .find(|attribute| attribute.oid.matches(OID_ID_AA_SIGNING_CERTIFICATE_V2))
        .expect("signingCertificateV2 attribute");
    let signing = SigningCertificateV2::from_attribute(attribute).unwrap();
    // The fixture TSA was configured with ess_cert_id_chain: signer + CA.
    assert_eq!(signing.certs.len(), 2);
    assert!(signing.matches_certificate(&tsa).unwrap());
    assert!(
        signing.certs[0].hash_algorithm.is_none(),
        "SHA-256 default must be omitted"
    );
    // The signing certificate entry carries no issuerSerial in OpenSSL's
    // default output, only the chain entry does.
    assert!(signing.certs[0].issuer_serial.is_none());
    assert!(signing.certs[1].issuer_serial.is_some());
    // Tampering with the hash breaks matching.
    let mut tampered = signing;
    tampered.certs[0].cert_hash[0] ^= 1;
    assert!(!tampered.matches_certificate(&tsa).unwrap());

    // The TSTInfo imprint is the SHA-256 of the fixture payload.
    let info = response.basic().unwrap();
    assert_eq!(
        MessageImprint::for_data(PAYLOAD, Hash::Sha256)
            .unwrap()
            .hashed_message,
        info.message_imprint.hashed_message
    );
}

// ---------------------------------------------------------------------------
// OpenSSL CLI interop (skipped when the binary is absent)
// ---------------------------------------------------------------------------

struct OpenSsl {
    binary: String,
    library_path: String,
    config: std::path::PathBuf,
}

fn openssl() -> Option<OpenSsl> {
    if let Ok(binary) = std::env::var("CROWN_OPENSSL") {
        return Some(OpenSsl {
            binary,
            library_path: std::env::var("CROWN_OPENSSL_LIB").unwrap_or_default(),
            config: write_temp("openssl.cnf", b""),
        });
    }
    let binary = "/home/loongtao/crown-ref/openssl/apps/openssl".to_string();
    if std::path::Path::new(&binary).exists() {
        Some(OpenSsl {
            binary,
            library_path: "/home/loongtao/crown-ref/openssl".to_string(),
            config: write_temp("openssl.cnf", b""),
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
            .env("OPENSSL_CONF", &self.config)
            .output()
            .unwrap_or_else(|err| panic!("run openssl: {err}"))
    }
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("crown_ts_{}_{name}", std::process::id()));
    path
}

fn write_temp(name: &str, data: &[u8]) -> std::path::PathBuf {
    let path = temp_path(name);
    std::fs::write(&path, data).unwrap();
    path
}

fn data_path(name: &str) -> String {
    format!("{}{name}", BASE)
}

fn assert_openssl_ok(output: &std::process::Output, what: &str) {
    assert!(
        output.status.success(),
        "{what}: openssl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Write a minimal `openssl ts -reply` configuration next to `tag` and run
/// `openssl ts -reply` with the given query.
fn openssl_ts_reply(openssl: &OpenSsl, tag: &str, query: &[u8]) -> Vec<u8> {
    let query_path = write_temp(&format!("{tag}_query.der"), query);
    let serial_path = write_temp(&format!("{tag}_serial"), b"01");
    let config = format!(
        "[tsa]\ndefault_tsa = tsa_config1\n\n[tsa_config1]\n\
         serial = {}\n\
         signer_digest = sha256\n\
         default_policy = {POLICY}\n\
         crypto_device = builtin\n\
         digests = sha256, sha512, sha1\n",
        serial_path.display()
    );
    let config_path = write_temp(&format!("{tag}_tsa.cnf"), config.as_bytes());
    let output_path = temp_path(&format!("{tag}_response.der"));
    let result = openssl.run(&[
        "ts",
        "-reply",
        "-config",
        config_path.to_str().unwrap(),
        "-queryfile",
        query_path.to_str().unwrap(),
        "-inkey",
        &data_path("ts_tsa_key.pem"),
        "-signer",
        &data_path("ts_tsa.pem"),
        "-chain",
        &data_path("ts_ca.pem"),
        "-out",
        output_path.to_str().unwrap(),
    ]);
    let response = std::fs::read(&output_path).unwrap_or_default();
    let _ = std::fs::remove_file(&query_path);
    let _ = std::fs::remove_file(&serial_path);
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&output_path);
    assert_openssl_ok(&result, tag);
    assert!(!response.is_empty(), "{tag}: empty OpenSSL response");
    response
}

/// Run `openssl ts -verify` over a crown-built response.
fn openssl_ts_verify(
    openssl: &OpenSsl,
    tag: &str,
    query: &[u8],
    response: &[u8],
    ca_file: &str,
    untrusted: Option<&str>,
) {
    let query_path = write_temp(&format!("{tag}_query.der"), query);
    let response_path = write_temp(&format!("{tag}_response.der"), response);
    let mut args = vec![
        "ts",
        "-verify",
        "-queryfile",
        query_path.to_str().unwrap(),
        "-in",
        response_path.to_str().unwrap(),
        "-CAfile",
        ca_file,
    ];
    if let Some(untrusted) = untrusted {
        args.push("-untrusted");
        args.push(untrusted);
    }
    let result = openssl.run(&args);
    let _ = std::fs::remove_file(&query_path);
    let _ = std::fs::remove_file(&response_path);
    assert_openssl_ok(&result, tag);
}

#[test]
fn openssl_verifies_crown_rsa_response() {
    let Some(openssl) = openssl() else {
        eprintln!(
            "skipping: set CROWN_OPENSSL to the OpenSSL binary to run interop; \
             manual: openssl ts -verify -queryfile ts_query_sha256.der \
             -in crown_response.der -CAfile ts_ca.pem -untrusted ts_tsa.pem"
        );
        return;
    };
    let rng = &mut TestRng(11);
    let signer = openssl_tsa_signer().signing_time(sample_time());
    let request = TimeStampReq::parse(&read("ts_query_sha256.der")).unwrap();
    let mut checked = 0;

    // Granted response from OpenSSL's own query.
    let response = signer
        .reply(
            &request,
            policy(),
            &[0x0b, 0xad],
            sample_time(),
            Some(Accuracy {
                seconds: Some(1),
                millis: None,
                micros: None,
            }),
            rng,
        )
        .unwrap();
    openssl_ts_verify(
        &openssl,
        "rsa",
        &read("ts_query_sha256.der"),
        &response.encode(),
        &data_path("ts_ca.pem"),
        Some(&data_path("ts_tsa.pem")),
    );
    checked += 1;

    // A SHA-512 request must also verify.
    let request = TimeStampReq::parse(&read("ts_query_sha512.der")).unwrap();
    let response = signer
        .reply(&request, policy(), &[0x0c], sample_time(), None, rng)
        .unwrap();
    openssl_ts_verify(
        &openssl,
        "rsa512",
        &read("ts_query_sha512.der"),
        &response.encode(),
        &data_path("ts_ca.pem"),
        Some(&data_path("ts_tsa.pem")),
    );
    checked += 1;

    assert!(checked >= 2, "only {checked} crown responses verified");
}

#[test]
fn openssl_verifies_crown_ecdsa_response() {
    let Some(openssl) = openssl() else {
        eprintln!(
            "skipping: set CROWN_OPENSSL to the OpenSSL binary to run interop; \
             manual: openssl ts -verify -queryfile ts_query_sha256.der \
             -in crown_ec_response.der -CAfile ec_tsa.pem"
        );
        return;
    };
    let rng = &mut TestRng(12);
    let key = private_key("ec_pkcs8.pem");
    let algorithm = SignatureAlgorithm::Ecdsa(Hash::Sha256);
    let certificate = Certificate::self_signed(
        Name::from_common_name("crown EC TSA interop"),
        algorithm,
        &key,
        crown::asn1::time::Asn1Time::new(2026, 1, 1, 0, 0, 0, true).unwrap(),
        crown::asn1::time::Asn1Time::new(2046, 1, 1, 0, 0, 0, true).unwrap(),
        vec![
            Extension::new(
                crown::asn1::oid::ObjectIdentifier::new(oid::OID_BASIC_CONSTRAINTS).unwrap(),
                true,
                BasicConstraints::default().encode(),
            ),
            Extension::new(
                crown::asn1::oid::ObjectIdentifier::new(oid::OID_KEY_USAGE).unwrap(),
                true,
                KeyUsage {
                    digital_signature: true,
                    ..Default::default()
                }
                .encode(),
            ),
            Extension::new(
                crown::asn1::oid::ObjectIdentifier::new(oid::OID_EXTENDED_KEY_USAGE).unwrap(),
                true,
                ExtendedKeyUsage {
                    purposes: vec![crown::asn1::oid::ObjectIdentifier::new(
                        oid::OID_KP_TIME_STAMPING,
                    )
                    .unwrap()],
                }
                .encode(),
            ),
        ],
        rng,
    )
    .unwrap();
    let signer = TimeStampSigner::new(certificate.clone(), key, Vec::new(), algorithm);
    let request = TimeStampReq::parse(&read("ts_query_sha256.der")).unwrap();
    let response = signer
        .reply(&request, policy(), &[0x01], sample_time(), None, rng)
        .unwrap();
    let ca_path = write_temp("ec_tsa.pem", certificate.to_pem().as_bytes());
    openssl_ts_verify(
        &openssl,
        "ec",
        &read("ts_query_sha256.der"),
        &response.encode(),
        ca_path.to_str().unwrap(),
        None,
    );
    let _ = std::fs::remove_file(&ca_path);
}

#[test]
fn openssl_replies_to_crown_query() {
    let Some(openssl) = openssl() else {
        eprintln!(
            "skipping: set CROWN_OPENSSL to the OpenSSL binary to run interop; \
             manual: openssl ts -reply -config tsa.cnf -queryfile crown_query.der \
             -inkey ts_tsa_key.pem -signer ts_tsa.pem -chain ts_ca.pem \
             -out openssl_response.der"
        );
        return;
    };
    let mut request = TimeStampReq::for_data(PAYLOAD, Hash::Sha256, true).unwrap();
    request.nonce = Some(vec![0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04]);
    request.req_policy = Some(policy());

    let response_der = openssl_ts_reply(&openssl, "crown", &request.encode());
    let response = TimeStampResp::parse(&response_der).unwrap();
    assert!(response.is_granted(), "OpenSSL rejected the crown query");
    let tsa = certificate("ts_tsa.pem");
    let info = response.verify(&tsa).unwrap();
    assert_eq!(info.message_imprint, request.message_imprint);
    assert_eq!(info.nonce, request.nonce);
    assert_eq!(info.policy.to_dotted_string(), POLICY);
    response.verify_request(&tsa, &request).unwrap();
    assert!(response
        .verify_request(
            &tsa,
            &TimeStampReq::for_data(PAYLOAD, Hash::Sha512, true).unwrap()
        )
        .is_err());
}
