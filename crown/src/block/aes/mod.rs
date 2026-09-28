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

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) mod aesni;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
mod bsaes;

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
                    let (enc_key, dec_key) = if aesni::supported() {
                        (aesni::set_encrypt_key(key), aesni::set_decrypt_key(key))
                    } else if crate::block::aes::asm::vpaes_supported() {
                        (
                            crate::block::aes::asm::vpaes_set_encrypt_key(key),
                            crate::block::aes::asm::vpaes_set_decrypt_key(key),
                        )
                    } else {
                        (ttable::set_encrypt_key(key), ttable::set_decrypt_key(key))
                    };
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

    /// AES-NI-format encrypt schedule (the stitch consumes this layout).
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    pub fn enc_schedule(&self) -> (ttable::AesKey, bool) {
        (self.enc_key, aesni::supported())
    }

    pub fn encrypt_block_internal(&self, inout: &mut [u8]) {
        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        {
            if aesni::supported() {
                aesni::encrypt_block(inout, &self.enc_key);
            } else if crate::block::aes::asm::vpaes_supported() {
                crate::block::aes::asm::vpaes_encrypt_block(inout, &self.enc_key);
            } else {
                ttable::encrypt_block(inout, &self.enc_key);
            }
        }
        #[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
        encrypt_block(self, inout);
    }

    /// CBC encrypt/decrypt of full blocks in place. `enc` selects direction.
    /// The IV is updated to the last ciphertext block. Uses the fused
    /// aesni/bsaes CBC routines when available.
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    pub fn cbc_blocks(&self, inout: &mut [u8], iv: &mut [u8; 16], enc: bool) {
        if aesni::supported() {
            // aesni_cbc_encrypt runs aesdec, so it needs the *decryption*
            // schedule when decypting (aesni_set_decrypt_key).
            let key = if enc { &self.enc_key } else { &self.dec_key };
            aesni::cbc_encrypt(inout, key, iv, enc);
            return;
        }
        if crate::block::aes::bsaes::supported() {
            // bsaes consumes the conventional FIPS-197 schedule (ttable
            // format), which is what enc_key/dec_key hold when AES-NI is off.
            let key = if enc { &self.enc_key } else { &self.dec_key };
            let ptr = inout.as_mut_ptr();
            let (ip, op) = unsafe {
                (
                    core::slice::from_raw_parts(ptr as *const u8, inout.len()),
                    core::slice::from_raw_parts_mut(ptr, inout.len()),
                )
            };
            crate::block::aes::bsaes::cbc_encrypt(ip, op, key, iv, enc);
            return;
        }
        // fall through to per-block software
        let n = inout.len() / 16;
        if n == 0 {
            return;
        }
        let mut prev_ct = *iv;
        let mut saved = [0u8; 16];
        if enc {
            for i in 0..n {
                let blk = &mut inout[i * 16..i * 16 + 16];
                for j in 0..16 {
                    blk[j] ^= prev_ct[j];
                }
                self.encrypt_block_internal(blk);
                prev_ct.copy_from_slice(blk);
            }
        } else {
            for i in 0..n {
                saved.copy_from_slice(&inout[i * 16..i * 16 + 16]);
                let blk = &mut inout[i * 16..i * 16 + 16];
                self.decrypt_block(blk);
                for j in 0..16 {
                    blk[j] ^= prev_ct[j];
                }
                prev_ct = saved;
            }
        }
        *iv = prev_ct;
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
        {
            if aesni::supported() {
                aesni::encrypt_block(inout, &self.enc_key);
            } else if crate::block::aes::asm::vpaes_supported() {
                crate::block::aes::asm::vpaes_encrypt_block(inout, &self.enc_key);
            } else {
                ttable::encrypt_block(inout, &self.enc_key);
            }
        }
        #[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
        encrypt_block(self, inout);
    }

    fn decrypt_block(&self, inout: &mut [u8]) {
        if inout.len() < Self::BLOCK_SIZE {
            panic!("crypto/aes: output not full block");
        }

        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        {
            if aesni::supported() {
                aesni::decrypt_block(inout, &self.dec_key);
            } else if crate::block::aes::asm::vpaes_supported() {
                crate::block::aes::asm::vpaes_decrypt_block(inout, &self.dec_key);
            } else {
                ttable::decrypt_block(inout, &self.dec_key);
            }
        }
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
        Self {
            rounds: 0,
            enc: [0; 60],
            dec: [0; 60],
        }
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
