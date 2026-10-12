use crate::crypto_err;
use crown::core::CoreRead;
use napi::bindgen_prelude::*;

/// PBKDF2-HMAC-SHA256.
#[napi]
pub fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32, length: u32) -> Buffer {
    Buffer::from(crown::password_hash::pbkdf2::key(
        password,
        salt,
        iterations,
        length as usize,
        crown::hash::sha256::new256,
    ))
}

/// HKDF-Extract + Expand with SHA-256. `info` may be empty.
#[napi]
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], length: u32) -> Result<Buffer> {
    let prk = crown::kdf::hkdf::extract(crown::hash::sha256::new256, ikm, salt);
    let mut exp = crown::kdf::hkdf::expand(crown::hash::sha256::new256, &prk, info);
    let mut out = vec![0u8; length as usize];
    exp.read_exact(&mut out)
        .map_err(|e| crypto_err("hkdf", e))?;
    Ok(Buffer::from(out))
}

/// TLS 1.2 PRF with SHA-256. `seed` is the label+seed material.
#[napi]
pub fn tls1_prf(secret: &[u8], seed: &[u8], length: u32) -> Result<Buffer> {
    crown::kdf::tls1_prf::derive(
        crown::envelope::EvpHash::new_sha256_hmac,
        secret,
        seed,
        length as usize,
    )
    .map(Buffer::from)
    .map_err(|e| crypto_err("tls1_prf", e))
}

/// SSKDF (hash-based) with SHA-256.
#[napi]
pub fn sskdf(secret: &[u8], info: &[u8], length: u32) -> Result<Buffer> {
    crown::kdf::sskdf::derive_hash(
        crown::envelope::EvpHash::new_sha256,
        secret,
        info,
        length as usize,
    )
    .map(Buffer::from)
    .map_err(|e| crypto_err("sskdf", e))
}

/// X963KDF with SHA-256.
#[napi]
pub fn x963_kdf(secret: &[u8], info: &[u8], length: u32) -> Result<Buffer> {
    crown::kdf::sskdf::x963_derive_hash(
        crown::envelope::EvpHash::new_sha256,
        secret,
        info,
        length as usize,
    )
    .map(Buffer::from)
    .map_err(|e| crypto_err("x963_kdf", e))
}

/// HOTP (RFC 4226).
#[napi]
pub fn hotp(key: &[u8], counter: f64, digits: u32) -> u32 {
    crown::otp::hotp(key, counter as u64, digits as usize)
}

/// TOTP (RFC 6238).
#[napi]
pub fn totp(key: &[u8], time: f64, step: f64, digits: u32, t0: f64) -> u32 {
    crown::otp::totp(key, time as u64, step as u64, digits as usize, t0 as u64)
}
