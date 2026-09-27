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
    "../testvectors_v1/sm4_gcm_test.json",
    "../testvectors_v1/seed_ccm_test.json",
    "../testvectors_v1/seed_gcm_test.json",
];

/// Single-AAD SIV vectors (`ct` is the tag followed by the ciphertext) and the
/// AEAD-shaped ones (the nonce is the last AAD element).
pub const SIV_TESTS: &[&str] = &[
    "aes_siv_cmac_test.json",
    "aead_aes_siv_cmac_test.json",
    "../testvectors_v1/aead_aes_siv_cmac_test.json",
];

pub fn get_aead_test(file: &str) -> Root {
    let path = format!("{}/{}", BASE_DIR, file);
    let s = std::fs::read_to_string(path).unwrap();

    serde_json::from_str(&s).unwrap_or_else(|err| panic!("deserialize {file} failed: {err}"))
}
