use crate::wycheproof::BASE_DIR;

typify::import_types!(schema = "tests/wycheproof/aead.json");

pub const AEAD_TESTS: &[&str] = &[
    "chacha20_poly1305_test.json",
    "xchacha20_poly1305_test.json",
    "aes_gcm_test.json",
    "aes_eax_test.json",
    "../testvectors_v1/aes_ccm_test.json",
    "../testvectors_v1/aria_gcm_test.json",
    "../testvectors_v1/aria_ccm_test.json",
    "../testvectors_v1/camellia_ccm_test.json",
    "../testvectors_v1/sm4_ccm_test.json",
];

pub fn get_aead_test(file: &str) -> Root {
    let path = format!("{}/{}", BASE_DIR, file);
    let s = std::fs::read_to_string(path).unwrap();

    serde_json::from_str(&s).unwrap_or_else(|err| panic!("deserialize {file} failed: {err}"))
}
