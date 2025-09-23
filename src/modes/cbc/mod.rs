//! Cipher block chaining (CBC) mode.
//!
//! CBC provides confidentiality by xoring (chaining) each plaintext block
//! with the previous ciphertext block before applying the block cipher.
//!
//! See NIST SP 800-38A, pp 10-11

#[cfg(test)]
mod tests;

mod decrypter;
pub use decrypter::*;

mod encryptor;
pub use encryptor::*;

use crate::block::BlockCipher;

/// CBC mode structure
struct CbcImpl<B: BlockCipher> {
    b: B,
    block_size: usize,
    iv: Vec<u8>,
    tmp: Vec<u8>,
}

impl<B: BlockCipher> CbcImpl<B> {
    fn new(b: B, iv: &[u8]) -> Self {
        let block_size = b.block_size();
        Self {
            b,
            block_size,
            iv: iv.to_vec(),
            tmp: vec![0u8; block_size],
        }
    }
}
