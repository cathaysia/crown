//! Module blowfish implements Bruce Schneier's Blowfish encryption algorithm.
//!
//! # WARNING
//! Blowfish is a legacy cipher and its short block size makes it vulnerable to
//! birthday bound attacks (see <https://sweet32.info>). It should only be used
//! where compatibility with legacy systems, not security, is the goal.
//!

mod block;
mod consts;

#[cfg(test)]
mod tests;

pub(crate) use block::*;

use consts::{P, S0, S1, S2, S3};

use crate::{
    aead::ocb::OcbGeneric,
    block::{BlockCipher, BlockCipherMarker},
    error::{CryptoError, CryptoResult},
};

// A Cipher is an instance of Blowfish encryption using a particular key.
pub struct Blowfish {
    p: [u32; 18],
    s0: [u32; 256],
    s1: [u32; 256],
    s2: [u32; 256],
    s3: [u32; 256],
}

impl BlockCipherMarker for Blowfish {}

impl OcbGeneric for Blowfish {}

impl Blowfish {
    pub const BLOCK_SIZE: usize = 8;
    /// Creates and returns a Blowfish cipher.
    ///
    /// **key**: The key argument should be the Blowfish key, from 1 to 56 bytes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if !(1..=56).contains(&key.len()) {
            return Err(CryptoError::InvalidKeySize {
                expected: "1..=56",
                actual: key.len(),
            });
        }
        let mut result = Self::init();
        expand_key(key, &mut result);
        Ok(result)
    }

    /// Creates a returns a Cipher that folds a salt into its key
    /// schedule. For most purposes, [Self::new], instead of [Self::new_salted], is
    /// sufficient and desirable.
    ///
    /// # Note
    /// For bcrypt compatibility, the key can be over 56
    /// bytes.
    pub fn new_salted(key: &[u8], salt: &[u8]) -> CryptoResult<Self> {
        if salt.is_empty() {
            return Self::new(key);
        }
        let k = key.len();
        if k < 1 {
            return Err(CryptoError::InvalidKeySize {
                expected: "> 1",
                actual: k,
            });
        }
        let mut result = Self::init();
        expand_key_with_salt(key, salt, &mut result);
        Ok(result)
    }

    fn init() -> Self {
        Self {
            p: P,
            s0: S0,
            s1: S1,
            s2: S2,
            s3: S3,
        }
    }
}

impl BlockCipher for Blowfish {
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    fn encrypt(&self, inout: &mut [u8]) {
        let l = ((inout[0] as u32) << 24)
            | ((inout[1] as u32) << 16)
            | ((inout[2] as u32) << 8)
            | (inout[3] as u32);
        let r = ((inout[4] as u32) << 24)
            | ((inout[5] as u32) << 16)
            | ((inout[6] as u32) << 8)
            | (inout[7] as u32);
        let (l, r) = encrypt_block(l, r, self);
        inout[0] = (l >> 24) as u8;
        inout[1] = (l >> 16) as u8;
        inout[2] = (l >> 8) as u8;
        inout[3] = l as u8;
        inout[4] = (r >> 24) as u8;
        inout[5] = (r >> 16) as u8;
        inout[6] = (r >> 8) as u8;
        inout[7] = r as u8;
    }

    fn decrypt(&self, inout: &mut [u8]) {
        let l = ((inout[0] as u32) << 24)
            | ((inout[1] as u32) << 16)
            | ((inout[2] as u32) << 8)
            | (inout[3] as u32);
        let r = ((inout[4] as u32) << 24)
            | ((inout[5] as u32) << 16)
            | ((inout[6] as u32) << 8)
            | (inout[7] as u32);
        let (l, r) = decrypt_block(l, r, self);
        inout[0] = (l >> 24) as u8;
        inout[1] = (l >> 16) as u8;
        inout[2] = (l >> 8) as u8;
        inout[3] = l as u8;
        inout[4] = (r >> 24) as u8;
        inout[5] = (r >> 16) as u8;
        inout[6] = (r >> 8) as u8;
        inout[7] = r as u8;
    }
}
