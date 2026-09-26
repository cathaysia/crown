//! PBKDF1 key derivation from PKCS #5 v1.5 (RFC 8018 section 5.1), ported
//! from OpenSSL `providers/implementations/kdfs/pbkdf1.c`.
//!
//! PBKDF1 is the legacy password-based KDF: it iterates the digest over its
//! own output and is limited to producing at most one digest worth of key
//! material. Only kept for compatibility with existing encrypted data.

#[cfg(test)]
mod tests;

use crate::core::CoreWrite;
use crate::error::{CryptoError, CryptoResult};
use crate::hash::HashUser;
use crate::kdf::HashFactory;

/// Derive `key_len` bytes from the password and salt, iterating the digest
/// `iter` times. `key_len` must not exceed the digest output size.
pub fn derive(
    hash: HashFactory,
    pass: &[u8],
    salt: &[u8],
    iter: u64,
    key_len: usize,
) -> CryptoResult<alloc::vec::Vec<u8>> {
    if iter == 0 {
        return Err(CryptoError::StrError(
            "pbkdf1: iteration count must be at least 1",
        ));
    }
    if key_len == 0 {
        return Err(CryptoError::InvalidLength);
    }

    let mut h = hash()?;
    let md_size = h.size();
    if key_len > md_size {
        return Err(CryptoError::StrError(
            "pbkdf1: requested key length too large",
        ));
    }

    h.write(pass)?;
    h.write(salt)?;
    let mut t = h.sum();

    for _ in 1..iter {
        let mut h = hash()?;
        h.write(&t)?;
        t = h.sum();
    }

    Ok(t[..key_len].to_vec())
}
