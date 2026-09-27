use crate::wycheproof::BASE_DIR;

typify::import_types!(schema = "tests/wycheproof/eddsa.json");

pub const EDDSA_TESTS: &[&str] = &["eddsa_test.json", "../testvectors_v1/ed25519_test.json"];

pub fn get_eddsa_test(file: &str) -> EddsaTestFile {
    let path = format!("{}/{}", BASE_DIR, file);
    let s = std::fs::read_to_string(path).unwrap();

    serde_json::from_str(&s).unwrap_or_else(|err| panic!("deserialize {file} failed: {err}"))
}
