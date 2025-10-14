mod consts;
use consts::*;

pub(crate) mod cbc;
#[cfg(feature = "alloc")]
pub(crate) mod ctr;
mod generic;

mod noasm;
use noasm::*;

pub(crate) mod gcm;

#[cfg(all(target_arch = "x86_64", feature = "unstable"))]
mod x86_64;

#[cfg(test)]
mod tests;

#[cfg(feature = "alloc")]
use crate::modes::{cfb::CfbMarker, ofb::OfbMarker};

use crate::{
    aead::ocb3::Ocb3Marker,
    block::BlockCipher,
    error::{CryptoError, CryptoResult},
};

const AES128_KEY_SIZE: usize = 16;
const AES192_KEY_SIZE: usize = 24;
const AES256_KEY_SIZE: usize = 32;

const AES128_ROUNDS: usize = 10;
const AES192_ROUNDS: usize = 12;
const AES256_ROUNDS: usize = 14;

#[derive(Clone)]
pub struct Aes {
    block: BlockExpanded,
}

#[cfg(feature = "alloc")]
impl OfbMarker for Aes {}

#[cfg(feature = "alloc")]
impl CfbMarker for Aes {}

impl Ocb3Marker for Aes {}

impl Aes {
    pub const BLOCK_SIZE: usize = 16;

    /// creates and returns a new [cipher.Block].
    /// The key argument should be the AES key,
    /// either 16, 24, or 32 bytes to select
    /// AES-128, AES-192, or AES-256.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        match key.len() {
            AES128_KEY_SIZE | AES192_KEY_SIZE | AES256_KEY_SIZE => {
                let mut block = BlockExpanded {
                    rounds: 0,
                    enc: [0; 60],
                    dec: [0; 60],
                };
                block.expand(key);
                Ok(Aes { block })
            }
            len => Err(CryptoError::InvalidKeySize {
                expected: "16 | 24 | 32",
                actual: len,
            }),
        }
    }

    pub fn encrypt_block_internal(&self, inout: &mut [u8]) {
        encrypt_block(self, inout);
    }
}

impl BlockCipher for Aes {
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    fn encrypt_block(&self, inout: &mut [u8]) {
        if inout.len() < Self::BLOCK_SIZE {
            panic!("crypto/aes: inout not full block");
        }

        encrypt_block(self, inout);
    }

    fn decrypt_block(&self, inout: &mut [u8]) {
        if inout.len() < Self::BLOCK_SIZE {
            panic!("crypto/aes: output not full block");
        }

        decrypt_block(self, inout);
    }
}

#[derive(Clone)]
struct BlockExpanded {
    pub rounds: usize,
    pub enc: [u32; 60],
    pub dec: [u32; 60],
}

impl BlockExpanded {
    fn expand(&mut self, key: &[u8]) {
        match key.len() {
            AES128_KEY_SIZE => self.rounds = AES128_ROUNDS,
            AES192_KEY_SIZE => self.rounds = AES192_ROUNDS,
            AES256_KEY_SIZE => self.rounds = AES256_ROUNDS,
            _ => unreachable!(),
        }
        self.expand_key_generic(key);
    }

    pub fn round_keys_size(&self) -> usize {
        (self.rounds + 1) * (128 / 32)
    }
}
