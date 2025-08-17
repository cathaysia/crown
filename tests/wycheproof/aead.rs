use crate::wycheproof::BASE_DIR;

typify::import_types!(schema = "tests/wycheproof/aead.json");

pub const AEAD_TESTS: &[&str] = &[
    "chacha20_poly1305_test.json",
    "xchacha20_poly1305_test.json",
];

pub fn get_aead_test(file: &str) -> Root {
    let path = format!("{}/{}", BASE_DIR, file);
    let s = std::fs::read_to_string(path).unwrap();

    serde_json::from_str(&s).unwrap_or_else(|err| panic!("deserialize {file} failed: {err}"))
}
