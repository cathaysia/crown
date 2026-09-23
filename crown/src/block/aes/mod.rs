mod consts;
use consts::*;

#[cfg(feature = "alloc")]
pub(crate) mod cbc;
#[cfg(feature = "alloc")]
pub(crate) mod ctr;
mod generic;

#[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
mod noasm;
#[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
use noasm::*;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
mod asm;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
mod ttable;

#[cfg(feature = "alloc")]
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
    /// Software schedule; kept for the no-asm path and as a test oracle.
    #[cfg_attr(all(feature = "asm", target_arch = "x86_64"), allow(dead_code))]
    block: BlockExpanded,
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    enc_key: ttable::AesKey,
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    dec_key: ttable::AesKey,
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
                let block = BlockExpanded {
                    rounds: 0,
                    enc: [0; 60],
                    dec: [0; 60],
                };
                #[cfg(all(feature = "asm", target_arch = "x86_64"))]
                {
                    let enc_key = ttable::set_encrypt_key(key);
                    let dec_key = ttable::set_decrypt_key(key);
                    Ok(Aes {
                        block,
                        enc_key,
                        dec_key,
                    })
                }
                #[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
                {
                    let mut block = block;
                    block.expand(key);
                    Ok(Aes { block })
                }
            }
            len => Err(CryptoError::InvalidKeySize {
                expected: "16 | 24 | 32",
                actual: len,
            }),
        }
    }

    pub fn encrypt_block_internal(&self, inout: &mut [u8]) {
        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        ttable::encrypt_block(inout, &self.enc_key);
        #[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
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

        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        ttable::encrypt_block(inout, &self.enc_key);
        #[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
        encrypt_block(self, inout);
    }

    fn decrypt_block(&self, inout: &mut [u8]) {
        if inout.len() < Self::BLOCK_SIZE {
            panic!("crypto/aes: output not full block");
        }

        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        ttable::decrypt_block(inout, &self.dec_key);
        #[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
        decrypt_block(self, inout);
    }
}

#[derive(Clone)]
pub(crate) struct BlockExpanded {
    pub rounds: usize,
    pub enc: [u32; 60],
    pub dec: [u32; 60],
}

#[cfg(test)]
impl Default for BlockExpanded {
    fn default() -> Self {
        Self { rounds: 0, enc: [0; 60], dec: [0; 60] }
    }
}

#[allow(dead_code)] // software key schedule; unused when asm owns key setup
impl BlockExpanded {
    pub(crate) fn expand(&mut self, key: &[u8]) {
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
