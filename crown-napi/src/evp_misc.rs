use crate::crypto_err;
use napi::bindgen_prelude::*;

#[napi]
pub fn aes_key_wrap(key: &[u8], plaintext: &[u8]) -> Result<Buffer> {
    crown::envelope::aes_key_wrap(key, plaintext)
        .map(Buffer::from)
        .map_err(|e| crypto_err("aes_key_wrap", e))
}

#[napi]
pub fn aes_key_unwrap(key: &[u8], ciphertext: &[u8]) -> Result<Buffer> {
    crown::envelope::aes_key_unwrap(key, ciphertext)
        .map(Buffer::from)
        .map_err(|e| crypto_err("aes_key_unwrap", e))
}

#[napi]
pub fn aes_key_wrap_padded(key: &[u8], plaintext: &[u8]) -> Result<Buffer> {
    crown::envelope::aes_key_wrap_padded(key, plaintext)
        .map(Buffer::from)
        .map_err(|e| crypto_err("aes_key_wrap_padded", e))
}

#[napi]
pub fn aes_key_unwrap_padded(key: &[u8], ciphertext: &[u8]) -> Result<Buffer> {
    crown::envelope::aes_key_unwrap_padded(key, ciphertext)
        .map(Buffer::from)
        .map_err(|e| crypto_err("aes_key_unwrap_padded", e))
}

#[napi]
pub fn ff1_encrypt_decimal(key: &[u8], tweak: &[u8], input: String) -> Result<String> {
    crown::envelope::ff1_encrypt_decimal(key, tweak, &input)
        .map_err(|e| crypto_err("ff1_encrypt_decimal", e))
}

#[napi]
pub fn ff1_decrypt_decimal(key: &[u8], tweak: &[u8], input: String) -> Result<String> {
    crown::envelope::ff1_decrypt_decimal(key, tweak, &input)
        .map_err(|e| crypto_err("ff1_decrypt_decimal", e))
}
