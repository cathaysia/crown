use crate::wycheproof::BASE_DIR;

typify::import_types!(schema = "tests/wycheproof/hkdf.json");

pub const HMAC_TESTS: &[&str] = &[
    "hkdf_sha1_test.json",
    "hkdf_sha256_test.json",
    "hkdf_sha384_test.json",
    "hkdf_sha512_test.json",
];

pub fn get_hkdf_test(file: &str) -> Root {
    let path = format!("{}/{}", BASE_DIR, file);
    let s = std::fs::read_to_string(path).unwrap();

    serde_json::from_str(&s).unwrap_or_else(|err| panic!("deserialize {file} failed: {err}"))
}
