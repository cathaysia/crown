//! CMS integration tests: OpenSSL-generated fixtures and crown-built
//! `EnvelopedData`/`EncryptedData`/`DigestedData` artifacts.
//!
//! Every fixture under `tests/data/pki/cms_*` produced by the vendored
//! OpenSSL 3.x CLI is parsed and, where applicable, decrypted. The reverse
//! direction runs the OpenSSL CLI over crown-built artifacts when the binary
//! exists (`CROWN_OPENSSL` overrides the default path).

use crown::cms::{
    AuthEnvelopedData, Cipher, ContentInfo, DigestedData, EncryptedData, EnvelopedData,
    EnvelopedDataBuilder,
};
use crown::rng::Rng;
use crown::x509::algorithm::Hash;
use crown::x509::cert::Certificate;
use crown::x509::keys::{PrivateKey, PrivateKeyInfo};

const BASE: &str = "tests/data/pki/";
const PAYLOAD: &[u8] = b"crown pkcs7 test payload\n";

/// OpenSSL canonicalises text input to CRLF unless `-binary` is given.
const OPENSSL_PAYLOAD: &[u8] = b"crown pkcs7 test payload\r\n";

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

fn enveloped(name: &str) -> EnvelopedData {
    let der = read(name);
    let info =
        ContentInfo::parse(&der).unwrap_or_else(|err| panic!("content info {name}: {err:?}"));
    assert_eq!(info.encode(), der, "{name}: ContentInfo re-encode");
    EnvelopedData::from_content_info(&info)
        .unwrap_or_else(|err| panic!("enveloped {name}: {err:?}"))
}

fn auth_enveloped(name: &str) -> AuthEnvelopedData {
    let der = read(name);
    let info =
        ContentInfo::parse(&der).unwrap_or_else(|err| panic!("content info {name}: {err:?}"));
    assert_eq!(info.encode(), der, "{name}: ContentInfo re-encode");
    AuthEnvelopedData::from_content_info(&info)
        .unwrap_or_else(|err| panic!("auth enveloped {name}: {err:?}"))
}

// ---------------------------------------------------------------------------
// OpenSSL fixtures: parse and decrypt
// ---------------------------------------------------------------------------

#[test]
fn openssl_rsa_enveloped_fixtures_decrypt() {
    let key = private_key("rsa_pkcs8.pem");
    let cert = certificate("leaf.pem");
    let mut checked = 0;
    for (name, expected_cipher) in [
        // `openssl cms -encrypt ... leaf.pem`: AES-256-CBC + RSA PKCS#1 v1.5.
        ("cms_env_rsa.der", Cipher::Aes256Cbc),
        // `-keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256`.
        ("cms_env_rsa_oaep.der", Cipher::Aes256Cbc),
        // `-des3`: DES-EDE3-CBC content encryption.
        ("cms_env_3des.der", Cipher::DesEde3Cbc),
    ] {
        let der = read(name);
        let data = enveloped(name);
        assert_eq!(data.version, 0, "{name}: version");
        assert!(
            data.encrypted_content_info
                .content_type
                .matches(crown::asn1::oid::OID_PKCS7_DATA),
            "{name}: content type"
        );
        assert_eq!(data.recipient_infos.len(), 1, "{name}: recipients");
        assert_eq!(data.to_content_info().encode(), der, "{name}: re-encode");
        let cipher = crown::cms::ContentCipher::parse(
            &data.encrypted_content_info.content_encryption_algorithm,
        )
        .unwrap();
        assert_eq!(cipher.cipher(), expected_cipher, "{name}: cipher");
        assert_eq!(
            data.decrypt_with_key(&key, &cert).unwrap(),
            OPENSSL_PAYLOAD,
            "{name}: decrypt"
        );
        checked += 1;
    }
    assert!(checked >= 3, "only {checked} RSA fixtures decrypted");
}

#[test]
fn openssl_password_fixture_decrypts() {
    let data = enveloped("cms_env_pwri.der");
    // OpenSSL sets version 3 for a password recipient.
    assert_eq!(data.version, 3);
    assert!(matches!(
        data.recipient_infos.first(),
        Some(crown::cms::RecipientInfo::Password(_))
    ));
    assert_eq!(
        data.decrypt_with_password(b"crown-test").unwrap(),
        OPENSSL_PAYLOAD
    );
    // Wrong password must fail.
    assert!(data.decrypt_with_password(b"wrong-password").is_err());
}

#[test]
fn openssl_key_agreement_fixture_decrypts() {
    let data = enveloped("cms_env_ec.der");
    assert_eq!(data.version, 2);
    let key = private_key("ec_pkcs8.pem");
    let cert = certificate("ec.pem");
    assert_eq!(data.decrypt_with_key(&key, &cert).unwrap(), OPENSSL_PAYLOAD);
    // A non-matching certificate must not select the recipient.
    let rsa_cert = certificate("leaf.pem");
    assert!(data.decrypt_with_key(&key, &rsa_cert).is_err());
}

#[test]
fn openssl_kek_fixture_decrypts() {
    let data = enveloped("cms_env_kek.der");
    assert_eq!(data.version, 2);
    let kek = [0u8; 32];
    assert_eq!(&data.recipient_infos.len(), &1);
    let Some(crown::cms::RecipientInfo::Kek(info)) = data.recipient_infos.first() else {
        panic!("expected a KEK recipient");
    };
    assert_eq!(info.version, 4);
    assert_eq!(info.kekid.key_id, vec![0xde, 0xad, 0xbe, 0xef, 0x01]);
    // The fixture was made with -secretkey 0001..1f.
    let mut kek_bytes = [0u8; 32];
    for (i, byte) in kek_bytes.iter_mut().enumerate() {
        *byte = i as u8;
    }
    assert_eq!(
        data.decrypt_with_kek(&kek_bytes, &[0xde, 0xad, 0xbe, 0xef, 0x01])
            .unwrap(),
        OPENSSL_PAYLOAD
    );
    assert!(data
        .decrypt_with_kek(&kek, &[0xde, 0xad, 0xbe, 0xef, 0x01])
        .is_err());
    assert!(data.decrypt_with_kek(&kek_bytes, b"other").is_err());
}

#[test]
fn openssl_encrypted_data_fixture_decrypts() {
    let der = read("cms_env_encdata.der");
    let info = ContentInfo::parse(&der).unwrap();
    let data = EncryptedData::from_content_info(&info).unwrap();
    assert_eq!(data.version, 0);
    assert_eq!(data.to_content_info().encode(), der);
    let key: Vec<u8> = (0u8..16).collect();
    assert_eq!(data.decrypt_with_key(&key).unwrap(), OPENSSL_PAYLOAD);
    assert!(data.decrypt_with_key(&[0u8; 16]).is_err());
}

#[test]
fn openssl_digested_fixture_verifies() {
    let der = read("cms_dig_sha256.der");
    let info = ContentInfo::parse(&der).unwrap();
    let data = DigestedData::from_content_info(&info).unwrap();
    assert_eq!(data.version, 0);
    assert_eq!(data.to_content_info().encode(), der);
    data.verify().unwrap();
    assert_eq!(data.content().unwrap(), OPENSSL_PAYLOAD);
    // Tampering with the content must fail verification.
    let mut tampered = data.clone();
    if let Some(content) = tampered.encap_content_info.content.as_mut() {
        content[0] ^= 1;
    }
    assert!(tampered.verify().is_err());
}

#[test]
fn openssl_auth_enveloped_fixture_decrypts() {
    // `openssl cms -encrypt -aes-256-gcm` emits AuthEnvelopedData (RFC 5083)
    // with the GCM tag in the `mac` field.
    let der = read("cms_env_gcm.der");
    let info = ContentInfo::parse(&der).unwrap();
    assert!(
        info.content_type
            .matches(&[1, 2, 840, 113549, 1, 9, 16, 1, 23]),
        "expected id-smime-ct-authEnvelopedData"
    );
    let data = auth_enveloped("cms_env_gcm.der");
    assert_eq!(data.version, 0);
    assert_eq!(data.mac.len(), 16);
    assert_eq!(data.to_content_info().encode(), der, "re-encode");
    let key = private_key("rsa_pkcs8.pem");
    let cert = certificate("leaf.pem");
    assert_eq!(data.decrypt_with_key(&key, &cert).unwrap(), OPENSSL_PAYLOAD);

    // A tampered tag or ciphertext must fail authentication.
    let mut tampered = data.clone();
    tampered.mac[0] ^= 1;
    assert!(tampered.decrypt_with_key(&key, &cert).is_err());
    let mut tampered = data;
    tampered
        .auth_encrypted_content_info
        .encrypted_content
        .as_mut()
        .unwrap()[0] ^= 1;
    assert!(tampered.decrypt_with_key(&key, &cert).is_err());
}

// ---------------------------------------------------------------------------
// Crown-built structures
// ---------------------------------------------------------------------------

#[test]
fn crown_rsa_enveloped_round_trip() {
    let rng = &mut TestRng(1);
    let cert = certificate("leaf.pem");
    let key = private_key("rsa_pkcs8.pem");
    for cipher in [
        Cipher::Aes128Cbc,
        Cipher::Aes192Cbc,
        Cipher::Aes256Cbc,
        Cipher::DesEde3Cbc,
    ] {
        let built = EnvelopedDataBuilder::new(PAYLOAD.to_vec())
            .add_rsa_recipient(&cert, cipher, rng)
            .build(rng)
            .unwrap();
        assert_eq!(built.version, 0);
        let der = built.to_content_info().encode();
        let parsed = enveloped_from_der(&der);
        assert_eq!(parsed.to_content_info().encode(), der);
        assert_eq!(parsed.decrypt_with_key(&key, &cert).unwrap(), PAYLOAD);
        // PEM round trip (label "CMS").
        let pem = parsed.to_pem();
        assert!(pem.starts_with("-----BEGIN CMS-----"));
        assert_eq!(
            EnvelopedData::from_pem(&pem)
                .unwrap()
                .to_content_info()
                .encode(),
            der
        );
    }
}

#[test]
fn crown_oaep_enveloped_round_trip() {
    let rng = &mut TestRng(2);
    let cert = certificate("leaf.pem");
    let key = private_key("rsa_pkcs8.pem");
    let built = EnvelopedDataBuilder::new(PAYLOAD.to_vec())
        .add_rsa_oaep_recipient(&cert, Cipher::Aes256Cbc, Hash::Sha256, rng)
        .build(rng)
        .unwrap();
    assert_eq!(built.decrypt_with_key(&key, &cert).unwrap(), PAYLOAD);
}

#[test]
fn crown_password_enveloped_round_trip() {
    let rng = &mut TestRng(3);
    let cert = certificate("leaf.pem");
    let built = EnvelopedDataBuilder::new(PAYLOAD.to_vec())
        .add_rsa_recipient(&cert, Cipher::Aes256Cbc, rng)
        .add_password_recipient(b"crown-pass", Cipher::Aes256Cbc, 2048)
        .build(rng)
        .unwrap();
    // A mixed recipient set with a password recipient is version 3.
    assert_eq!(built.version, 3);
    assert_eq!(built.recipient_infos.len(), 2);
    assert_eq!(built.decrypt_with_password(b"crown-pass").unwrap(), PAYLOAD);
    assert!(built.decrypt_with_password(b"nope").is_err());
    // The password recipient derives its KEK from PBKDF2-SHA-256.
    let Some(crown::cms::RecipientInfo::Password(info)) = built
        .recipient_infos
        .iter()
        .find(|ri| matches!(ri, crown::cms::RecipientInfo::Password(_)))
    else {
        panic!("missing password recipient");
    };
    let kdf = info.key_derivation_algorithm.as_ref().unwrap();
    assert!(kdf.oid.matches(crown::asn1::oid::OID_PBKDF2));
    let params = kdf.parameters.as_ref().unwrap();
    let mut reader = crown::asn1::der::Reader::new(params);
    let mut seq = reader.read_sequence().unwrap();
    seq.read_octet_string().unwrap(); // salt
    seq.read_integer_i64().unwrap(); // iterations
    let prf = crown::x509::algorithm::AlgorithmIdentifier::parse(&mut seq).unwrap();
    assert!(prf.oid.matches(crown::asn1::oid::OID_HMAC_SHA256));
}

#[test]
fn crown_kek_enveloped_round_trip() {
    let rng = &mut TestRng(4);
    let cert = certificate("leaf.pem");
    let key = private_key("rsa_pkcs8.pem");
    let kek = [0x5au8; 32];
    let built = EnvelopedDataBuilder::new(PAYLOAD.to_vec())
        .add_kek_recipient(&kek, b"crown-kek", Cipher::Aes256Cbc)
        .add_rsa_recipient(&cert, Cipher::Aes256Cbc, rng)
        .build(rng)
        .unwrap();
    assert_eq!(built.version, 2);
    assert_eq!(built.decrypt_with_kek(&kek, b"crown-kek").unwrap(), PAYLOAD);
    assert!(built.decrypt_with_kek(&[0u8; 32], b"crown-kek").is_err());
    assert!(built.decrypt_with_kek(&kek, b"other").is_err());
    assert_eq!(built.decrypt_with_key(&key, &cert).unwrap(), PAYLOAD);
}

#[test]
fn crown_key_agreement_round_trip() {
    let rng = &mut TestRng(5);
    let cert = certificate("ec.pem");
    let key = private_key("ec_pkcs8.pem");
    let built = EnvelopedDataBuilder::new(PAYLOAD.to_vec())
        .add_key_agree_recipient(&cert, Cipher::Aes256Cbc, rng)
        .build(rng)
        .unwrap();
    assert_eq!(built.version, 2);
    // The ephemeral originator key is emitted with the curve OID.
    let Some(crown::cms::RecipientInfo::KeyAgree(info)) = built.recipient_infos.first() else {
        panic!("expected a key agreement recipient");
    };
    assert_eq!(info.version, 3);
    assert!(!info.recipient_encrypted_keys.is_empty());
    assert_eq!(built.decrypt_with_key(&key, &cert).unwrap(), PAYLOAD);
    // Wrong private key type must fail.
    let rsa_key = private_key("rsa_pkcs8.pem");
    assert!(built.decrypt_with_key(&rsa_key, &cert).is_err());
}

#[test]
fn crown_aead_enveloped_round_trip() {
    let rng = &mut TestRng(6);
    let cert = certificate("leaf.pem");
    let key = private_key("rsa_pkcs8.pem");
    for cipher in [Cipher::Aes128Gcm, Cipher::Aes256Gcm] {
        let built = EnvelopedDataBuilder::new(PAYLOAD.to_vec())
            .add_rsa_recipient(&cert, cipher, rng)
            .build(rng)
            .unwrap();
        let parsed = enveloped_from_der(&built.to_content_info().encode());
        assert_eq!(parsed.decrypt_with_key(&key, &cert).unwrap(), PAYLOAD);
        // The GCM tag is appended to the ciphertext.
        let encrypted = parsed
            .encrypted_content_info
            .encrypted_content
            .as_deref()
            .unwrap();
        assert_eq!(encrypted.len(), PAYLOAD.len() + 16);
        // Flipping a ciphertext bit must fail authentication.
        let mut tampered = parsed.clone();
        tampered
            .encrypted_content_info
            .encrypted_content
            .as_mut()
            .unwrap()[0] ^= 1;
        assert!(tampered.decrypt_with_key(&key, &cert).is_err());
    }
}

#[test]
fn crown_auth_enveloped_round_trip() {
    let rng = &mut TestRng(8);
    let cert = certificate("leaf.pem");
    let key = private_key("rsa_pkcs8.pem");
    let built = EnvelopedDataBuilder::new(PAYLOAD.to_vec())
        .add_rsa_recipient(&cert, Cipher::Aes256Gcm, rng)
        .build_auth_enveloped(rng)
        .unwrap();
    assert_eq!(built.mac.len(), 16);
    assert!(built.auth_attrs.is_empty());
    assert!(built.associated_data().is_empty());
    let parsed = auth_enveloped_from_der(&built.to_content_info().encode());
    assert_eq!(
        parsed.to_content_info().encode(),
        built.to_content_info().encode()
    );
    assert_eq!(parsed.decrypt_with_key(&key, &cert).unwrap(), PAYLOAD);
    // The content is the AEAD ciphertext only; the tag lives in `mac`.
    assert_eq!(
        parsed
            .auth_encrypted_content_info
            .encrypted_content
            .as_ref()
            .unwrap()
            .len(),
        PAYLOAD.len()
    );

    // A non-AEAD cipher cannot produce AuthEnvelopedData.
    assert!(EnvelopedDataBuilder::new(PAYLOAD.to_vec())
        .add_rsa_recipient(&cert, Cipher::Aes256Cbc, rng)
        .build_auth_enveloped(rng)
        .is_err());
}

fn auth_enveloped_from_der(der: &[u8]) -> AuthEnvelopedData {
    let info = ContentInfo::parse(der).unwrap();
    AuthEnvelopedData::from_content_info(&info).unwrap()
}

#[test]
fn crown_encrypted_data_round_trip() {
    let rng = &mut TestRng(7);
    let raw_key: Vec<u8> = (16u8..32).collect();
    let data = EncryptedData::encrypt(PAYLOAD, Cipher::Aes128Cbc, &raw_key, rng).unwrap();
    let parsed = EncryptedData::from_content_info(&data.to_content_info()).unwrap();
    assert_eq!(parsed.decrypt_with_key(&raw_key).unwrap(), PAYLOAD);
    assert!(parsed.decrypt_with_key(&[0u8; 16]).is_err());
    assert!(parsed.to_pem().starts_with("-----BEGIN CMS-----"));
    let pem = parsed.to_pem();
    assert_eq!(
        EncryptedData::from_pem(&pem).unwrap().encode(),
        parsed.encode()
    );

    // Password-based (PBES2) variant.
    let password = EncryptedData::encrypt_with_password(
        PAYLOAD,
        b"crown-enc-pass",
        Cipher::Aes256Cbc,
        1000,
        rng,
    )
    .unwrap();
    let parsed = EncryptedData::from_content_info(&password.to_content_info()).unwrap();
    assert_eq!(
        parsed.decrypt_with_password(b"crown-enc-pass").unwrap(),
        PAYLOAD
    );
    assert!(parsed.decrypt_with_password(b"wrong").is_err());
}

#[test]
fn crown_digested_round_trip() {
    for hash in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
        let data = DigestedData::create(PAYLOAD, hash).unwrap();
        let parsed = DigestedData::from_content_info(&data.to_content_info()).unwrap();
        parsed.verify().unwrap();
        assert_eq!(parsed.content().unwrap(), PAYLOAD);
        let pem = parsed.to_pem();
        assert_eq!(
            DigestedData::from_pem(&pem).unwrap().encode(),
            parsed.encode()
        );
    }
}

fn enveloped_from_der(der: &[u8]) -> EnvelopedData {
    let info = ContentInfo::parse(der).unwrap();
    EnvelopedData::from_content_info(&info).unwrap()
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
}

fn temp_file(name: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("crown_cms_{}_{name}", std::process::id()));
    path
}

fn assert_openssl_ok(output: &std::process::Output, what: &str) {
    assert!(
        output.status.success(),
        "{what}: openssl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Write `der` to a temp file, decrypt it with the given extra OpenSSL `cms`
/// arguments and return the output.
fn openssl_cms_decrypt(openssl: &OpenSsl, tag: &str, der: &[u8], args: &[&str]) -> Vec<u8> {
    openssl_cms_operation(openssl, "-decrypt", tag, der, args)
}

/// Run `openssl cms <operation>` over `der` and return the `-out` file.
fn openssl_cms_operation(
    openssl: &OpenSsl,
    operation: &str,
    tag: &str,
    der: &[u8],
    args: &[&str],
) -> Vec<u8> {
    let input = temp_file(&format!("{tag}.der"));
    let output = temp_file(&format!("{tag}.out"));
    std::fs::write(&input, der).unwrap();
    let mut full = vec![
        "cms",
        operation,
        "-inform",
        "DER",
        "-in",
        input.to_str().unwrap(),
        "-out",
        output.to_str().unwrap(),
    ];
    full.extend_from_slice(args);
    let result = openssl.run(&full);
    let data = std::fs::read(&output).unwrap_or_default();
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    assert_openssl_ok(&result, tag);
    data
}

#[test]
fn openssl_decrypts_crown_enveloped_data() {
    let Some(openssl) = openssl() else {
        eprintln!(
            "skipping: set CROWN_OPENSSL to the OpenSSL binary to run interop; \
             manual: openssl cms -decrypt -inform DER -in artifact.der -recip leaf.pem -inkey rsa_pkcs8.pem"
        );
        return;
    };
    let rng = &mut TestRng(11);
    let cert = certificate("leaf.pem");
    let ec_cert = certificate("ec.pem");
    let mut checked = 0;

    // RSA PKCS#1 v1.5 (AES-256-CBC).
    let rsa = EnvelopedDataBuilder::new(PAYLOAD.to_vec())
        .add_rsa_recipient(&cert, Cipher::Aes256Cbc, rng)
        .build(rng)
        .unwrap();
    assert_eq!(
        openssl_cms_decrypt(
            &openssl,
            "rsa",
            &rsa.to_content_info().encode(),
            &[
                "-recip",
                "tests/data/pki/leaf.pem",
                "-inkey",
                "tests/data/pki/rsa_pkcs8.pem"
            ],
        ),
        PAYLOAD
    );
    checked += 1;

    // RSA OAEP-SHA-256.
    let oaep = EnvelopedDataBuilder::new(PAYLOAD.to_vec())
        .add_rsa_oaep_recipient(&cert, Cipher::Aes256Cbc, Hash::Sha256, rng)
        .build(rng)
        .unwrap();
    assert_eq!(
        openssl_cms_decrypt(
            &openssl,
            "oaep",
            &oaep.to_content_info().encode(),
            &[
                "-recip",
                "tests/data/pki/leaf.pem",
                "-inkey",
                "tests/data/pki/rsa_pkcs8.pem"
            ],
        ),
        PAYLOAD
    );
    checked += 1;

    // ECDH key agreement (AES-256-CBC).
    let ec = EnvelopedDataBuilder::new(PAYLOAD.to_vec())
        .add_key_agree_recipient(&ec_cert, Cipher::Aes256Cbc, rng)
        .build(rng)
        .unwrap();
    assert_eq!(
        openssl_cms_decrypt(
            &openssl,
            "ec",
            &ec.to_content_info().encode(),
            &[
                "-recip",
                "tests/data/pki/ec.pem",
                "-inkey",
                "tests/data/pki/ec_pkcs8.pem"
            ],
        ),
        PAYLOAD
    );
    checked += 1;

    // Password recipient.
    let pwri = EnvelopedDataBuilder::new(PAYLOAD.to_vec())
        .add_password_recipient(b"crown-test", Cipher::Aes256Cbc, 2048)
        .build(rng)
        .unwrap();
    assert_eq!(
        openssl_cms_decrypt(
            &openssl,
            "pwri",
            &pwri.to_content_info().encode(),
            &["-pwri_password", "crown-test"],
        ),
        PAYLOAD
    );
    checked += 1;

    // KEK recipient (AES-256 key wrap).
    let mut kek = Vec::new();
    for byte in 0u8..32 {
        kek.push(byte);
    }
    let kek_hex = kek
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let kek_env = EnvelopedDataBuilder::new(PAYLOAD.to_vec())
        .add_kek_recipient(&kek, &[0xde, 0xad, 0xbe, 0xef], Cipher::Aes256Cbc)
        .build(rng)
        .unwrap();
    assert_eq!(
        openssl_cms_decrypt(
            &openssl,
            "kek",
            &kek_env.to_content_info().encode(),
            &["-secretkey", &kek_hex, "-secretkeyid", "deadbeef"],
        ),
        PAYLOAD
    );
    checked += 1;

    // AES-256-GCM in AuthEnvelopedData (RFC 5083).
    let aead = EnvelopedDataBuilder::new(PAYLOAD.to_vec())
        .add_rsa_recipient(&cert, Cipher::Aes256Gcm, rng)
        .build_auth_enveloped(rng)
        .unwrap();
    assert_eq!(
        openssl_cms_decrypt(
            &openssl,
            "gcm",
            &aead.to_content_info().encode(),
            &[
                "-recip",
                "tests/data/pki/leaf.pem",
                "-inkey",
                "tests/data/pki/rsa_pkcs8.pem"
            ],
        ),
        PAYLOAD
    );
    checked += 1;

    assert!(
        checked >= 6,
        "only {checked} crown artifacts decrypted by OpenSSL"
    );
}

#[test]
fn openssl_decrypts_crown_encrypted_data_and_digested_data() {
    let Some(openssl) = openssl() else {
        eprintln!(
            "skipping: set CROWN_OPENSSL to the OpenSSL binary to run interop; \
             manual: openssl cms -EncryptedData_decrypt -inform DER -in artifact.der -secretkey <hex>"
        );
        return;
    };
    let rng = &mut TestRng(12);
    let raw_key: Vec<u8> = (0u8..16).collect();
    let encrypted = EncryptedData::encrypt(PAYLOAD, Cipher::Aes128Cbc, &raw_key, rng).unwrap();
    let raw_key_hex = raw_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        openssl_cms_operation(
            &openssl,
            "-EncryptedData_decrypt",
            "encdata",
            &encrypted.to_content_info().encode(),
            &["-secretkey", &raw_key_hex],
        ),
        PAYLOAD
    );

    // `-digest_verify` is a different operation from `cms -decrypt`.
    let digested = DigestedData::create(PAYLOAD, Hash::Sha256).unwrap();
    let input = temp_file("dig.der");
    let output = temp_file("dig.out");
    std::fs::write(&input, digested.to_content_info().encode()).unwrap();
    let result = openssl.run(&[
        "cms",
        "-digest_verify",
        "-inform",
        "DER",
        "-in",
        input.to_str().unwrap(),
        "-out",
        output.to_str().unwrap(),
    ]);
    let data = std::fs::read(&output).unwrap_or_default();
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    assert_openssl_ok(&result, "digested");
    assert_eq!(data, PAYLOAD);
}
