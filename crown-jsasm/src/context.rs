/// https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-build-scripts
#[derive(serde::Serialize, serde::Deserialize)]
pub struct JsasmContext {
    feature: String,
    unix: bool,
    windows: bool,
    target_family: String,
    target_os: String,
    target_arch: String,
    target_vendor: String,
    target_env: String,
    target_abi: String,
    target_pointer_width: usize,
    target_endian: String,
    target_feature: String,
}

impl JsasmContext {
    pub fn new() -> Result<Self, std::env::VarError> {
        let feature = std::env::var("CARGO_CFG_FEATURE")?;
        let unix = std::env::var("CARGO_CFG_UNIX").is_ok();
        let windows = std::env::var("CARGO_CFG_WINDOWS").is_ok();
        let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY")?;
        let target_os = std::env::var("CARGO_CFG_TARGET_OS")?;
        let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH")?;
        let target_vendor = std::env::var("CARGO_CFG_TARGET_VENDOR")?;
        let target_env = std::env::var("CARGO_CFG_TARGET_ENV")?;
        let target_abi = std::env::var("CARGO_CFG_TARGET_ABI")?;
        let target_pointer_width = std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH")?
            .parse()
            .unwrap();
        let target_endian = std::env::var("CARGO_CFG_TARGET_ENDIAN")?;
        let target_feature = std::env::var("CARGO_CFG_TARGET_FEATURE")?;
        Ok(Self {
            feature,
            unix,
            windows,
            target_family,
            target_os,
            target_arch,
            target_vendor,
            target_env,
            target_abi,
            target_pointer_width,
            target_endian,
            target_feature,
        })
    }
}
