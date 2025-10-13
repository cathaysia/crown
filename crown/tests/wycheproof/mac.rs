use crate::wycheproof::BASE_DIR;

typify::import_types!(schema = "tests/wycheproof/mac.json");

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

pub fn get_mac_test(file: &str) -> MacTestFile {
    let path = format!("{}/{}", BASE_DIR, file);
    let s = std::fs::read_to_string(path).unwrap();

    serde_json::from_str(&s).unwrap_or_else(|err| panic!("deserialize {file} failed: {err}"))
}
