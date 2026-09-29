use wasm_bindgen::prelude::*;

/// PBKDF2-HMAC-SHA256.
#[wasm_bindgen]
pub fn pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    length: usize,
) -> Result<Vec<u8>, JsValue> {
    Ok(crown::password_hash::pbkdf2::key(
        password,
        salt,
        iterations,
        length,
        crown::hash::sha256::new256,
    ))
}

/// HKDF-Extract + Expand with SHA-256. `info` may be empty.
#[wasm_bindgen]
pub fn hkdf(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, JsValue> {
    use crown::core::CoreRead;
    let prk = crown::kdf::hkdf::extract(crown::hash::sha256::new256, ikm, salt);
    let mut exp = crown::kdf::hkdf::expand(crown::hash::sha256::new256, &prk, info);
    let mut out = vec![0u8; length];
    exp.read_exact(&mut out)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(out)
}

/// TLS 1.2 PRF with SHA-256. `seed` is the label+seed material.
#[wasm_bindgen]
pub fn tls1_prf(secret: &[u8], seed: &[u8], length: usize) -> Result<Vec<u8>, JsValue> {
    crown::kdf::tls1_prf::derive(
        crown::envelope::EvpHash::new_sha256_hmac,
        secret,
        seed,
        length,
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

/// SSKDF (hash-based) with SHA-256.
#[wasm_bindgen]
pub fn sskdf(secret: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, JsValue> {
    crown::kdf::sskdf::derive_hash(
        crown::envelope::EvpHash::new_sha256,
        secret,
        info,
        length,
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

/// X963KDF with SHA-256.
#[wasm_bindgen]
pub fn x963_kdf(secret: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, JsValue> {
    crown::kdf::sskdf::x963_derive_hash(
        crown::envelope::EvpHash::new_sha256,
        secret,
        info,
        length,
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

/// HOTP (RFC 4226).
#[wasm_bindgen]
pub fn hotp(key: &[u8], counter: f64, digits: usize) -> u32 {
    crown::otp::hotp(key, counter as u64, digits)
}

/// TOTP (RFC 6238).
#[wasm_bindgen]
pub fn totp(key: &[u8], time: f64, step: f64, digits: usize, t0: f64) -> u32 {
    crown::otp::totp(key, time as u64, step as u64, digits, t0 as u64)
}
