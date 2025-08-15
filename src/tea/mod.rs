//! TEA (Tiny Encryption Algorithm) implementation
//!
//! This module implements the TEA algorithm, as defined in Needham and
//! Wheeler's 1994 technical report, "TEA, a Tiny Encryption Algorithm". See
//! <http://www.cix.co.uk/~klockstone/tea.pdf> for details.
//!
//! TEA is a legacy cipher and its short block size makes it vulnerable to
//! birthday bound attacks (see <https://sweet32.info>). It should only be used
//! where compatibility with legacy systems, not security, is the goal.
//!
//! Deprecated: any new system should use AES (from crypto/aes, if necessary in
//! an AEAD mode like crypto/cipher.NewGCM) or XChaCha20-Poly1305 (from
//! golang.org/x/crypto/chacha20poly1305).

#[cfg(test)]
mod tests;

use bytes::BufMut;

use crate::cipher::marker::BlockCipherMarker;
use crate::cipher::BlockCipher;

use crate::error::CryptoError;

/// The TEA key schedule constant.
const DELTA: u32 = 0x9e3779b9;

/// The standard number of rounds in TEA.
const NUM_ROUNDS: usize = 64;

/// TEA cipher instance with a particular key.
pub struct Tea {
    key: [u8; 16],
    rounds: usize,
}

impl BlockCipherMarker for Tea {}

impl Tea {
    /// The size of a TEA block, in bytes.
    pub const BLOCK_SIZE: usize = 8;

    /// The size of a TEA key, in bytes.
    pub const KEY_SIZE: usize = 16;

    /// Creates a new TEA cipher instance with the standard number of rounds.
    /// The key must be exactly 16 bytes long.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        Self::new_with_rounds(key, NUM_ROUNDS)
    }

    /// Creates a new TEA cipher instance with a given number of rounds.
    /// The number of rounds must be even and the key must be exactly 16 bytes long.
    pub fn new_with_rounds(key: &[u8], rounds: usize) -> Result<Self, CryptoError> {
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize(key.len()));
        }

        if rounds & 1 != 0 {
            return Err(CryptoError::InvalidParameter(
                "odd number of rounds specified".to_string(),
            ));
        }

        let mut tea_key = [0u8; 16];
        tea_key.copy_from_slice(key);

        Ok(Tea {
            key: tea_key,
            rounds,
        })
    }
}

impl BlockCipher for Tea {
    /// Returns the TEA block size, which is eight bytes.
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    /// Encrypts the 8 byte buffer src using the key and stores the result in dst.
    /// Note that for amounts of data larger than a block, it is not safe to just
    /// call encrypt on successive blocks; instead, use an encryption mode like CBC.
    fn encrypt(&self, inout: &mut [u8]) {
        assert_eq!(
            inout.len(),
            Self::BLOCK_SIZE,
            "inout buffer must be exactly {} bytes",
            Self::BLOCK_SIZE
        );

        let mut v0 = u32::from_be_bytes([inout[0], inout[1], inout[2], inout[3]]);
        let mut v1 = u32::from_be_bytes([inout[4], inout[5], inout[6], inout[7]]);

        let k0 = u32::from_be_bytes([self.key[0], self.key[1], self.key[2], self.key[3]]);
        let k1 = u32::from_be_bytes([self.key[4], self.key[5], self.key[6], self.key[7]]);
        let k2 = u32::from_be_bytes([self.key[8], self.key[9], self.key[10], self.key[11]]);
        let k3 = u32::from_be_bytes([self.key[12], self.key[13], self.key[14], self.key[15]]);

        let mut sum = 0u32;

        for _ in 0..(self.rounds / 2) {
            sum = sum.wrapping_add(DELTA);
            v0 = v0.wrapping_add(
                ((v1 << 4).wrapping_add(k0))
                    ^ (v1.wrapping_add(sum))
                    ^ ((v1 >> 5).wrapping_add(k1)),
            );
            v1 = v1.wrapping_add(
                ((v0 << 4).wrapping_add(k2))
                    ^ (v0.wrapping_add(sum))
                    ^ ((v0 >> 5).wrapping_add(k3)),
            );
        }

        let mut inout = inout;
        inout.put_u32(v0);
        inout.put_u32(v1);
    }

    /// Decrypts the 8 byte buffer src using the key and stores the result in dst.
    fn decrypt(&self, inout: &mut [u8]) {
        assert_eq!(
            inout.len(),
            Self::BLOCK_SIZE,
            "inout buffer must be exactly {} bytes",
            Self::BLOCK_SIZE
        );

        let mut v0 = u32::from_be_bytes([inout[0], inout[1], inout[2], inout[3]]);
        let mut v1 = u32::from_be_bytes([inout[4], inout[5], inout[6], inout[7]]);

        let k0 = u32::from_be_bytes([self.key[0], self.key[1], self.key[2], self.key[3]]);
        let k1 = u32::from_be_bytes([self.key[4], self.key[5], self.key[6], self.key[7]]);
        let k2 = u32::from_be_bytes([self.key[8], self.key[9], self.key[10], self.key[11]]);
        let k3 = u32::from_be_bytes([self.key[12], self.key[13], self.key[14], self.key[15]]);

        let mut sum = DELTA.wrapping_mul(self.rounds as u32 / 2);

        for _ in 0..(self.rounds / 2) {
            v1 = v1.wrapping_sub(
                ((v0 << 4).wrapping_add(k2))
                    ^ (v0.wrapping_add(sum))
                    ^ ((v0 >> 5).wrapping_add(k3)),
            );
            v0 = v0.wrapping_sub(
                ((v1 << 4).wrapping_add(k0))
                    ^ (v1.wrapping_add(sum))
                    ^ ((v1 >> 5).wrapping_add(k1)),
            );
            sum = sum.wrapping_sub(DELTA);
        }

        inout[0..4].copy_from_slice(&v0.to_be_bytes());
        inout[4..8].copy_from_slice(&v1.to_be_bytes());
    }
}
