use crate::wycheproof::BASE_DIR;

typify::import_types!(schema = "tests/wycheproof/ind_cpa_test_schema.json");

pub const IND_CPA_TESTS: &[&str] = &["aes_cbc_pkcs5_test.json"];

pub fn get_ind_cpa_test(file: &str) -> Root {
    let path = format!("{}/{}", BASE_DIR, file);
    let s = std::fs::read_to_string(path).unwrap();

    serde_json::from_str(&s).unwrap_or_else(|err| panic!("deserialize {file} failed: {err}"))
}
