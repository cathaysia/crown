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

use bytes::{Buf, BufMut};

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
    const BLOCK_SIZE: usize = 8;

    /// The size of a TEA key, in bytes.
    const KEY_SIZE: usize = 16;

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

        if rounds % 2 != 0 {
            return Err(CryptoError::InvalidRound(rounds));
        }

        Ok(Tea {
            key: key.try_into().unwrap(),
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

        let (mut v0, mut v1) = {
            let mut inout = &*inout;
            (inout.get_u32(), inout.get_u32())
        };
        let (k0, k1, k2, k3) = {
            let mut key = self.key.as_slice();
            (key.get_u32(), key.get_u32(), key.get_u32(), key.get_u32())
        };

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

        let (mut v0, mut v1) = {
            let mut inout = &*inout;
            (inout.get_u32(), inout.get_u32())
        };
        let (k0, k1, k2, k3) = {
            let mut key = self.key.as_slice();
            (key.get_u32(), key.get_u32(), key.get_u32(), key.get_u32())
        };

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

        let mut inout = inout;
        inout.put_u32(v0);
        inout.put_u32(v1);
    }
}
