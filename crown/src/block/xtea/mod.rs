//! Module xtea implements XTEA encryption, as defined in Needham and Wheeler's
//! 1997 technical report, "Tea extensions."
//!
//! XTEA is a legacy cipher and its short block size makes it vulnerable to
//! birthday bound attacks (see <https://sweet32.info>). It should only be used
//! where compatibility with legacy systems, not security, is the goal.
//!
//! # WARNING
//!
//! Deprecated: any new system should use AES (from crypto/aes, if necessary in
//! an AEAD mode like crypto/cipher.NewGCM) or XChaCha20-Poly1305 (from
//! golang.org/x/crypto/chacha20poly1305).
//!
//! For details, see <http://www.cix.co.uk/~klockstone/xtea.pdf>

#[cfg(test)]
mod tests;

mod block;

use crate::{
    aead::ocb3::Ocb3Marker,
    block::{BlockCipher, BlockCipherMarker},
    error::{CryptoError, CryptoResult},
};

/// A Cipher is an instance of an XTEA cipher using a particular key.
pub struct Xtea {
    // table contains a series of precalculated values that are used each round.
    table: [u32; 64],
}

impl BlockCipherMarker for Xtea {}
impl Ocb3Marker for Xtea {}

impl Xtea {
    /// The XTEA block size in bytes.
    const BLOCK_SIZE: usize = 8;
    // XTEA is based on 64 rounds.
    const NUM_ROUNDS: usize = 64;

    /// Creates and returns a new Cipher.
    /// The key argument should be the XTEA key.
    /// XTEA only supports 128 bit (16 byte) keys.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeySize {
                expected: "16",
                actual: key.len(),
            });
        }

        let mut c = Xtea { table: [0; 64] };
        c.init(key);
        Ok(c)
    }

    /// Initializes the cipher context by creating a look up table
    /// of precalculated values that are based on the key.
    fn init(&mut self, key: &[u8]) {
        debug_assert_eq!(key.len(), 16);
        // Load the key into four u32s
        let mut k = [0u32; 4];
        (0..k.len()).for_each(|i| {
            let j = i << 2; // Multiply by 4
            k[i] = ((key[j] as u32) << 24)
                | ((key[j + 1] as u32) << 16)
                | ((key[j + 2] as u32) << 8)
                | (key[j + 3] as u32);
        });

        // Precalculate the table
        const DELTA: u32 = 0x9E3779B9;
        let mut sum = 0u32;

        // Two rounds of XTEA applied per loop
        let mut i = 0;
        while i < Self::NUM_ROUNDS {
            self.table[i] = sum.wrapping_add(k[(sum & 3) as usize]);
            i += 1;
            sum = sum.wrapping_add(DELTA);
            self.table[i] = sum.wrapping_add(k[((sum >> 11) & 3) as usize]);
            i += 1;
        }
    }
}

impl BlockCipher for Xtea {
    fn block_size(&self) -> usize {
        Xtea::BLOCK_SIZE
    }

    fn encrypt_block(&self, inout: &mut [u8]) {
        block::encrypt_block(self, inout);
    }

    fn decrypt_block(&self, inout: &mut [u8]) {
        block::decrypt_block(self, inout);
    }
}
