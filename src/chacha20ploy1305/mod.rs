//! Module chacha20poly1305 implements the ChaCha20-Poly1305 AEAD and its
//! extended nonce variant XChaCha20-Poly1305, as specified in RFC 8439 and
//! draft-irtf-cfrg-xchacha-01.

mod generic;

mod xchacha20poly1305;
pub use xchacha20poly1305::*;

#[cfg(test)]
mod tests;

use crate::cipher::Aead;
use crate::error::{CryptoError, CryptoResult};

// ChaCha20-Poly1305 AEAD implementation
pub struct ChaCha20Poly1305 {
    key: [u8; Self::KEY_SIZE],
}

impl ChaCha20Poly1305 {
    pub const KEY_SIZE: usize = 32;
    pub const NONCE_SIZE: usize = 12;
    pub const OVERHEAD: usize = 16;

    // New returns a ChaCha20-Poly1305 AEAD that uses the given 256-bit key
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize(key.len()));
        }

        let mut cipher_key = [0u8; Self::KEY_SIZE];
        cipher_key.copy_from_slice(key);

        Ok(Self { key: cipher_key })
    }

    // Placeholder implementations - these would call the actual crypto functions
    fn seal_impl(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        self.seal_generic(dst, nonce, plaintext, additional_data)
    }

    fn open_impl(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        self.open_generic(dst, nonce, ciphertext, additional_data)
    }
}

impl Aead for ChaCha20Poly1305 {
    fn seal(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != Self::NONCE_SIZE {
            panic!("chacha20poly1305: bad nonce length passed to Seal");
        }

        if plaintext.len() as u64 > (1u64 << 38) - 64 {
            panic!("chacha20poly1305: plaintext too large");
        }

        self.seal_impl(dst, nonce, plaintext, additional_data)
    }

    fn open(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != Self::NONCE_SIZE {
            panic!("chacha20poly1305: bad nonce length passed to Open");
        }

        if ciphertext.len() < 16 {
            return Err(CryptoError::AuthenticationFailed);
        }

        if ciphertext.len() as u64 > (1u64 << 38) - 48 {
            panic!("chacha20poly1305: ciphertext too large");
        }

        self.open_impl(dst, nonce, ciphertext, additional_data)
    }

    fn nonce_size() -> usize {
        Self::NONCE_SIZE
    }

    fn overhead() -> usize {
        Self::OVERHEAD
    }
}
