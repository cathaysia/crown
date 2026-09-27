use crate::wycheproof::BASE_DIR;

typify::import_types!(schema = "tests/wycheproof/mac.json");

/// The GMAC files carry an IV and so use the `MacWithIvTest` schema; it has
/// to live in its own module because typify emits a fixed set of helper items.
pub mod with_iv {
    typify::import_types!(schema = "tests/wycheproof/mac_with_iv.json");
}
pub use with_iv::MacWithIvTestFile;

pub const HMAC_TESTS: &[&str] = &[
    "hmac_sha1_test.json",
    "hmac_sha224_test.json",
    "hmac_sha256_test.json",
    "hmac_sha384_test.json",
    "hmac_sha3_224_test.json",
    "hmac_sha3_256_test.json",
    "hmac_sha3_384_test.json",
    "hmac_sha3_512_test.json",
    "hmac_sha512_test.json",
];

/// HMAC variants that only exist in `testvectors_v1`.
pub const HMAC_EXTRA_TESTS: &[&str] = &[
    "../testvectors_v1/hmac_sha512_224_test.json",
    "../testvectors_v1/hmac_sha512_256_test.json",
    "../testvectors_v1/hmac_sm3_test.json",
];

pub const CMAC_TESTS: &[&str] = &[
    "aes_cmac_test.json",
    "../testvectors_v1/aes_cmac_test.json",
    "../testvectors_v1/aria_cmac_test.json",
    "../testvectors_v1/camellia_cmac_test.json",
];

pub const KMAC_TESTS: &[&str] = &[
    "../testvectors_v1/kmac128_no_customization_test.json",
    "../testvectors_v1/kmac256_no_customization_test.json",
];

/// crown implements SipHash-2-4 (64- and 128-bit output); the file names
/// encode the compression/finalization round counts.
pub const SIPHASH_TESTS: &[&str] = &[
    "../testvectors_v1/siphash_2_4_test.json",
    "../testvectors_v1/siphashx_2_4_test.json",
];

pub const GMAC_TESTS: &[&str] = &["gmac_test.json", "../testvectors_v1/aes_gmac_test.json"];

pub fn get_mac_test(file: &str) -> MacTestFile {
    let path = format!("{}/{}", BASE_DIR, file);
    let s = std::fs::read_to_string(path).unwrap();

    serde_json::from_str(&s).unwrap_or_else(|err| panic!("deserialize {file} failed: {err}"))
}

pub fn get_mac_with_iv_test(file: &str) -> MacWithIvTestFile {
    let path = format!("{}/{}", BASE_DIR, file);
    let s = std::fs::read_to_string(path).unwrap();

    serde_json::from_str(&s).unwrap_or_else(|err| panic!("deserialize {file} failed: {err}"))
}
