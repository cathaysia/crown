mod generic;

#[cfg(test)]
mod tests;

use crate::error::{CryptoError, CryptoResult};

// Constants
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const OVERHEAD: usize = 16;

// ChaCha20-Poly1305 AEAD implementation
pub struct ChaCha20Poly1305 {
    key: [u8; KEY_SIZE],
}

impl ChaCha20Poly1305 {
    // New returns a ChaCha20-Poly1305 AEAD that uses the given 256-bit key
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeySize(key.len()));
        }

        let mut cipher_key = [0u8; KEY_SIZE];
        cipher_key.copy_from_slice(key);

        Ok(Self { key: cipher_key })
    }

    pub fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }

    pub fn overhead(&self) -> usize {
        OVERHEAD
    }

    pub fn seal(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != NONCE_SIZE {
            panic!("chacha20poly1305: bad nonce length passed to Seal");
        }

        if plaintext.len() as u64 > (1u64 << 38) - 64 {
            panic!("chacha20poly1305: plaintext too large");
        }

        self.seal_impl(dst, nonce, plaintext, additional_data)
    }

    pub fn open(
        &self,
        dst: &mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> CryptoResult<()> {
        if nonce.len() != NONCE_SIZE {
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

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
pub fn slice_for_append(input: &[u8], n: usize) -> (Vec<u8>, Vec<u8>) {
    let total = input.len() + n;
    let mut head = Vec::with_capacity(total);
    head.extend_from_slice(input);
    head.resize(total, 0);

    let tail = head[input.len()..].to_vec();
    (head, tail)
}
