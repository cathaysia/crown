#[cfg(test)]
mod tests;

mod consts;
use consts::*;

pub mod ctr;
mod generic;

use crate::error::{CryptoError, CryptoResult};

pub const BLOCK_SIZE: usize = 16;

const AES128_KEY_SIZE: usize = 16;
const AES192_KEY_SIZE: usize = 24;
const AES256_KEY_SIZE: usize = 32;

const AES128_ROUNDS: usize = 10;
const AES192_ROUNDS: usize = 12;
const AES256_ROUNDS: usize = 14;

pub struct BlockExpanded {
    pub rounds: usize,
    pub enc: [u32; 60],
    pub dec: [u32; 60],
}

impl BlockExpanded {
    pub fn round_keys_size(&self) -> usize {
        (self.rounds + 1) * (128 / 32)
    }
}

pub struct Block {
    block: BlockExpanded,
}

impl Block {
    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    pub fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
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

    pub fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
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

    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        match key.len() {
            AES128_KEY_SIZE | AES192_KEY_SIZE | AES256_KEY_SIZE => {
                let mut block = BlockExpanded {
                    rounds: 0,
                    enc: [0; 60],
                    dec: [0; 60],
                };
                new_block_expanded(&mut block, key);
                Ok(Block { block })
            }
            len => Err(CryptoError::InvalidKeySize(len)),
        }
    }

    pub fn encrypt_block_internal(&self, dst: &mut [u8], src: &[u8]) {
        encrypt_block(self, dst, src);
    }
}

fn new_block_expanded(c: &mut BlockExpanded, key: &[u8]) {
    match key.len() {
        AES128_KEY_SIZE => c.rounds = AES128_ROUNDS,
        AES192_KEY_SIZE => c.rounds = AES192_ROUNDS,
        AES256_KEY_SIZE => c.rounds = AES256_ROUNDS,
        _ => unreachable!(),
    }
    generic::expand_key_generic(c, key);
}

fn encrypt_block(c: &Block, dst: &mut [u8], src: &[u8]) {
    generic::encrypt_block_generic(&c.block, dst, src);
}

fn decrypt_block(c: &Block, dst: &mut [u8], src: &[u8]) {
    generic::decrypt_block_generic(&c.block, dst, src);
}

fn inexact_overlap(dst: &[u8], src: &[u8]) -> bool {
    let dst_ptr = dst.as_ptr() as usize;
    let src_ptr = src.as_ptr() as usize;
    let dst_end = dst_ptr + dst.len();
    let src_end = src_ptr + src.len();

    (dst_ptr < src_end && src_ptr < dst_end) && (dst_ptr != src_ptr)
}

// NewCipher creates and returns a new [cipher.Block].
// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
pub fn new_cipher(key: &[u8]) -> CryptoResult<Block> {
    Block::new(key)
}
