use crate::wycheproof::BASE_DIR;

typify::import_types!(schema = "tests/wycheproof/rsa.json");

/// PKCS#1 v1.5 signature verification. Only the digests crown builds a
/// `DigestInfo` for are listed: the SHA-3, SHA-512/224 and SHA-512/256 files
/// would otherwise be matched by hash length and use the wrong prefix.
pub const PKCS1_SIG_TESTS: &[&str] = &[
    "rsa_signature_test.json",
    "rsa_signature_2048_sha224_test.json",
    "rsa_signature_2048_sha256_test.json",
    "rsa_signature_2048_sha384_test.json",
    "rsa_signature_2048_sha512_test.json",
    "rsa_signature_3072_sha256_test.json",
    "rsa_signature_3072_sha384_test.json",
    "rsa_signature_3072_sha512_test.json",
    "rsa_signature_4096_sha384_test.json",
    "rsa_signature_4096_sha512_test.json",
];

pub const PSS_TESTS: &[&str] = &[
    "rsa_pss_2048_sha1_mgf1_20_test.json",
    "rsa_pss_2048_sha256_mgf1_0_test.json",
    "rsa_pss_2048_sha256_mgf1_32_test.json",
    "rsa_pss_2048_sha512_256_mgf1_28_test.json",
    "rsa_pss_2048_sha512_256_mgf1_32_test.json",
    "rsa_pss_3072_sha256_mgf1_32_test.json",
    "rsa_pss_4096_sha256_mgf1_32_test.json",
    "rsa_pss_4096_sha512_mgf1_32_test.json",
    "rsa_pss_misc_test.json",
];

pub const OAEP_TESTS: &[&str] = &[
    "rsa_oaep_2048_sha1_mgf1sha1_test.json",
    "rsa_oaep_2048_sha256_mgf1sha256_test.json",
    "rsa_oaep_2048_sha384_mgf1sha384_test.json",
    "rsa_oaep_2048_sha512_mgf1sha512_test.json",
    "rsa_oaep_3072_sha256_mgf1sha256_test.json",
    "rsa_oaep_4096_sha256_mgf1sha256_test.json",
    "rsa_oaep_4096_sha512_mgf1sha512_test.json",
    "rsa_oaep_misc_test.json",
];

pub const PKCS1_DECRYPT_TESTS: &[&str] = &[
    "rsa_pkcs1_2048_test.json",
    "rsa_pkcs1_3072_test.json",
    "rsa_pkcs1_4096_test.json",
];

/// PKCS#1 v1.5 signature *generation*: the groups carry a full private key
/// (PKCS#8) and the digest, and the encoding is deterministic.
pub const PKCS1_SIGN_TESTS: &[&str] = &["rsa_sig_gen_misc_test.json"];

pub fn get_rsa_test(file: &str) -> RsaTestFile {
    let path = format!("{}/{}", BASE_DIR, file);
    let s = std::fs::read_to_string(path).unwrap();

    serde_json::from_str(&s).unwrap_or_else(|err| panic!("deserialize {file} failed: {err}"))
}
