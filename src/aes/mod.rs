mod consts;
use consts::*;

pub mod cbc;
pub mod ctr;
mod generic;

mod noasm;
use noasm::*;

pub mod gcm;

#[cfg(test)]
mod tests;

use crate::{
    cipher::BlockCipher,
    error::{CryptoError, CryptoResult},
    utils::inexact_overlap,
};

pub const BLOCK_SIZE: usize = 16;

const AES128_KEY_SIZE: usize = 16;
const AES192_KEY_SIZE: usize = 24;
const AES256_KEY_SIZE: usize = 32;

const AES128_ROUNDS: usize = 10;
const AES192_ROUNDS: usize = 12;
const AES256_ROUNDS: usize = 14;

pub struct Aes {
    block: BlockExpanded,
}

impl Aes {
    // NewCipher creates and returns a new [cipher.Block].
    // The key argument should be the AES key,
    // either 16, 24, or 32 bytes to select
    // AES-128, AES-192, or AES-256.
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        match key.len() {
            AES128_KEY_SIZE | AES192_KEY_SIZE | AES256_KEY_SIZE => {
                let mut block = BlockExpanded {
                    rounds: 0,
                    enc: [0; 60],
                    dec: [0; 60],
                };
                BlockExpanded::expand(&mut block, key);
                Ok(Aes { block })
            }
            len => Err(CryptoError::InvalidKeySize(len)),
        }
    }

    pub fn encrypt_block_internal(&self, dst: &mut [u8], src: &[u8]) {
        encrypt_block(self, dst, src);
    }
}

impl BlockCipher for Aes {
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        if src.len() < BLOCK_SIZE {
            panic!("crypto/aes: input not full block");
        }
        if dst.len() < BLOCK_SIZE {
            panic!("crypto/aes: output not full block");
        }
        if inexact_overlap(&dst[..BLOCK_SIZE], &src[..BLOCK_SIZE]) {
            panic!("crypto/aes: invalid buffer overlap");
        }
        encrypt_block(self, dst, src);
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        if src.len() < BLOCK_SIZE {
            panic!("crypto/aes: input not full block");
        }
        if dst.len() < BLOCK_SIZE {
            panic!("crypto/aes: output not full block");
        }
        if inexact_overlap(&dst[..BLOCK_SIZE], &src[..BLOCK_SIZE]) {
            panic!("crypto/aes: invalid buffer overlap");
        }
        decrypt_block(self, dst, src);
    }
}

pub struct BlockExpanded {
    pub rounds: usize,
    pub enc: [u32; 60],
    pub dec: [u32; 60],
}

impl BlockExpanded {
    fn expand(c: &mut BlockExpanded, key: &[u8]) {
        match key.len() {
            AES128_KEY_SIZE => c.rounds = AES128_ROUNDS,
            AES192_KEY_SIZE => c.rounds = AES192_ROUNDS,
            AES256_KEY_SIZE => c.rounds = AES256_ROUNDS,
            _ => unreachable!(),
        }
        generic::expand_key_generic(c, key);
    }

    pub fn round_keys_size(&self) -> usize {
        (self.rounds + 1) * (128 / 32)
    }
}
