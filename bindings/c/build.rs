fn main() {
    #[cfg(feature = "cbindgen")]
    generate_cbindgen();
}

#[cfg(feature = "cbindgen")]
fn generate_cbindgen() {
    use std::env;
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let config = include_str!("./cbindgen.toml");
    let config: cbindgen::Config = toml::from_str(config).unwrap();

    cbindgen::Builder::new()
        .with_config(config)
        .with_crate(crate_dir)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("include/kittycrypto.h");
}
