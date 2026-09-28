//! Unified helpers for AES Key Wrap (RFC 3394/5649) and FF1 (SP 800-38G).

use crate::block::aes::Aes;
use crate::error::CryptoResult;
use crate::modes::ff1;
use crate::modes::kw;

/// AES Key Wrap (RFC 3394). `key` is the KEK (16/24/32 bytes).
pub fn aes_key_wrap(key: &[u8], plaintext: &[u8]) -> CryptoResult<alloc::vec::Vec<u8>> {
    let c = Aes::new(key)?;
    kw::key_wrap(&c, plaintext)
}

/// AES Key Unwrap (RFC 3394).
pub fn aes_key_unwrap(key: &[u8], ciphertext: &[u8]) -> CryptoResult<alloc::vec::Vec<u8>> {
    let c = Aes::new(key)?;
    kw::key_unwrap(&c, ciphertext)
}

/// AES Key Wrap with Padding (RFC 5649).
pub fn aes_key_wrap_padded(key: &[u8], plaintext: &[u8]) -> CryptoResult<alloc::vec::Vec<u8>> {
    let c = Aes::new(key)?;
    kw::key_wrap_padded(&c, plaintext)
}

/// AES Key Unwrap with Padding (RFC 5649).
pub fn aes_key_unwrap_padded(key: &[u8], ciphertext: &[u8]) -> CryptoResult<alloc::vec::Vec<u8>> {
    let c = Aes::new(key)?;
    kw::key_unwrap_padded(&c, ciphertext)
}

/// FF1 encrypt a numeral string in `radix` (2..=65536).
pub fn ff1_encrypt(
    key: &[u8],
    tweak: &[u8],
    radix: u32,
    input: &[u32],
) -> CryptoResult<alloc::vec::Vec<u32>> {
    ff1::ff1_encrypt(key, tweak, radix, input)
}

/// FF1 decrypt a numeral string in `radix` (2..=65536).
pub fn ff1_decrypt(
    key: &[u8],
    tweak: &[u8],
    radix: u32,
    input: &[u32],
) -> CryptoResult<alloc::vec::Vec<u32>> {
    ff1::ff1_decrypt(key, tweak, radix, input)
}

/// FF1 encrypt a decimal digit string (radix 10).
pub fn ff1_encrypt_decimal(key: &[u8], tweak: &[u8], s: &str) -> CryptoResult<alloc::string::String> {
    ff1::ff1_encrypt_decimal(key, tweak, s)
}

/// FF1 decrypt a decimal digit string (radix 10).
pub fn ff1_decrypt_decimal(key: &[u8], tweak: &[u8], s: &str) -> CryptoResult<alloc::string::String> {
    ff1::ff1_decrypt_decimal(key, tweak, s)
}
