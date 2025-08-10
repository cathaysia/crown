//! Package blowfish implements Bruce Schneier's Blowfish encryption algorithm.
//!
//! Blowfish is a legacy cipher and its short block size makes it vulnerable to
//! birthday bound attacks (see <https://sweet32.info>). It should only be used
//! where compatibility with legacy systems, not security, is the goal.
//!

mod block;
mod consts;

#[cfg(test)]
mod tests;

pub use block::{decrypt_block, encrypt_block, expand_key, expand_key_with_salt};
use consts::{P, S0, S1, S2, S3};

use crate::{
    cipher::{marker::BlockCipherMarker, BlockCipher},
    error::{CryptoError, CryptoResult},
};

// The Blowfish block size in bytes.
pub const BLOCK_SIZE: usize = 8;

// A Cipher is an instance of Blowfish encryption using a particular key.
pub struct Cipher {
    pub p: [u32; 18],
    pub s0: [u32; 256],
    pub s1: [u32; 256],
    pub s2: [u32; 256],
    pub s3: [u32; 256],
}

impl BlockCipherMarker for Cipher {}

impl Cipher {
    // NewCipher creates and returns a Cipher.
    // The key argument should be the Blowfish key, from 1 to 56 bytes.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        let k = key.len();
        if !(1..=56).contains(&k) {
            return Err(CryptoError::InvalidKeySize(k));
        }
        let mut result = Self::init();
        expand_key(key, &mut result);
        Ok(result)
    }

    // NewSaltedCipher creates a returns a Cipher that folds a salt into its key
    // schedule. For most purposes, NewCipher, instead of NewSaltedCipher, is
    // sufficient and desirable. For bcrypt compatibility, the key can be over 56
    // bytes.
    pub fn new_salted(key: &[u8], salt: &[u8]) -> CryptoResult<Self> {
        if salt.is_empty() {
            return Self::new(key);
        }
        let k = key.len();
        if k < 1 {
            return Err(CryptoError::InvalidKeySize(k));
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

impl BlockCipher for Cipher {
    // BlockSize returns the Blowfish block size, 8 bytes.
    // It is necessary to satisfy the Block interface in the
    // package "crypto/cipher".
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    // Encrypt encrypts the 8-byte buffer src using the key k
    // and stores the result in dst.
    // Note that for amounts of data larger than a block,
    // it is not safe to just call Encrypt on successive blocks;
    // instead, use an encryption mode like CBC (see crypto/cipher/cbc.go).
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        let l = ((src[0] as u32) << 24)
            | ((src[1] as u32) << 16)
            | ((src[2] as u32) << 8)
            | (src[3] as u32);
        let r = ((src[4] as u32) << 24)
            | ((src[5] as u32) << 16)
            | ((src[6] as u32) << 8)
            | (src[7] as u32);
        let (l, r) = encrypt_block(l, r, self);
        dst[0] = (l >> 24) as u8;
        dst[1] = (l >> 16) as u8;
        dst[2] = (l >> 8) as u8;
        dst[3] = l as u8;
        dst[4] = (r >> 24) as u8;
        dst[5] = (r >> 16) as u8;
        dst[6] = (r >> 8) as u8;
        dst[7] = r as u8;
    }

    // Decrypt decrypts the 8-byte buffer src using the key k
    // and stores the result in dst.
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        let l = ((src[0] as u32) << 24)
            | ((src[1] as u32) << 16)
            | ((src[2] as u32) << 8)
            | (src[3] as u32);
        let r = ((src[4] as u32) << 24)
            | ((src[5] as u32) << 16)
            | ((src[6] as u32) << 8)
            | (src[7] as u32);
        let (l, r) = decrypt_block(l, r, self);
        dst[0] = (l >> 24) as u8;
        dst[1] = (l >> 16) as u8;
        dst[2] = (l >> 8) as u8;
        dst[3] = l as u8;
        dst[4] = (r >> 24) as u8;
        dst[5] = (r >> 16) as u8;
        dst[6] = (r >> 8) as u8;
        dst[7] = r as u8;
    }
}
