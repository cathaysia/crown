//! Module chacha20poly1305 implements the ChaCha20-Poly1305 AEAD and its
//! extended nonce variant XChaCha20-Poly1305, as specified in RFC 8439 and
//! draft-irtf-cfrg-xchacha-01.

mod generic;

mod xchacha20poly1305;
pub use xchacha20poly1305::*;

#[cfg(test)]
mod tests;

use crate::aead::{Aead, AeadUser};
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
            return Err(CryptoError::InvalidKeySize {
                expected: "32",
                actual: key.len(),
            });
        }

        let mut cipher_key = [0u8; Self::KEY_SIZE];
        cipher_key.copy_from_slice(key);

        Ok(Self { key: cipher_key })
    }

    // Placeholder implementations - these would call the actual crypto functions
    fn seal_impl(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; 16]> {
        self.seal_generic(inout, nonce, additional_data)
    }

    fn open_impl(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        self.open_generic(inout, tag, nonce, additional_data)
    }
}

impl AeadUser for ChaCha20Poly1305 {
    fn nonce_size(&self) -> usize {
        Self::NONCE_SIZE
    }

    fn overhead(&self) -> usize {
        Self::OVERHEAD
    }
}

impl Aead<16> for ChaCha20Poly1305 {
    fn seal_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<[u8; 16]> {
        if nonce.len() != Self::NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: "12",
                actual: nonce.len(),
            });
        }

        if inout.len() as u64 > (1u64 << 38) - 64 {
            panic!("chacha20poly1305: plaintext too large");
        }

        self.seal_impl(inout, nonce, additional_data)
    }

    fn open_in_place_separate_tag(
        &self,
        inout: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != Self::NONCE_SIZE {
            panic!("chacha20poly1305: bad nonce length passed to Open");
        }

        if inout.len() as u64 > (1u64 << 38) - 48 {
            panic!("chacha20poly1305: ciphertext too large");
        }

        self.open_impl(inout, tag, nonce, additional_data)
    }
}
