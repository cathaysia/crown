//! CFB (Cipher Feedback) Mode implementation.
//!

use crate::block::BlockCipher;
use crate::block::BlockCipherMarker;
use crate::error::{CryptoError, CryptoResult};
use crate::stream::StreamCipher;
use crate::utils::copy;
use crate::utils::subtle::xor::xor_bytes;
use alloc::vec;
use alloc::vec::Vec;

#[cfg(test)]
mod tests;

/// CFB stream cipher implementation
struct CfbImpl<B: BlockCipher> {
    b: B,
    next: Vec<u8>,
    out: Vec<u8>,
    out_used: usize,
    decrypt: bool,
}

/// Trait for block ciphers that can be used with CFB mode
pub trait Cfb {
    /// Create a new CFB encryptor with the given IV
    fn to_cfb_encryptor(self, iv: &[u8]) -> CryptoResult<impl StreamCipher + 'static>;

    /// Create a new CFB decrypter with the given IV
    fn to_cfb_decryptor(self, iv: &[u8]) -> CryptoResult<impl StreamCipher + 'static>;

    /// Create a new CFB1 (1-bit feedback) encryptor with the given IV.
    fn to_cfb1_encryptor(self, iv: &[u8]) -> CryptoResult<impl StreamCipher + 'static>
    where
        Self: BlockCipher + Sized + 'static,
    {
        new_cfb_bits(self, iv, 1, false)
    }

    /// Create a new CFB1 (1-bit feedback) decrypter with the given IV.
    fn to_cfb1_decryptor(self, iv: &[u8]) -> CryptoResult<impl StreamCipher + 'static>
    where
        Self: BlockCipher + Sized + 'static,
    {
        new_cfb_bits(self, iv, 1, true)
    }

    /// Create a new CFB8 (8-bit feedback) encryptor with the given IV.
    fn to_cfb8_encryptor(self, iv: &[u8]) -> CryptoResult<impl StreamCipher + 'static>
    where
        Self: BlockCipher + Sized + 'static,
    {
        new_cfb_bits(self, iv, 8, false)
    }

    /// Create a new CFB8 (8-bit feedback) decrypter with the given IV.
    fn to_cfb8_decryptor(self, iv: &[u8]) -> CryptoResult<impl StreamCipher + 'static>
    where
        Self: BlockCipher + Sized + 'static,
    {
        new_cfb_bits(self, iv, 8, true)
    }
}

/// Marker trait for types that can be used with CFB
pub trait CfbMarker {}
impl<T: BlockCipherMarker> CfbMarker for T {}

impl<T> Cfb for T
where
    T: BlockCipher + CfbMarker + 'static,
{
    fn to_cfb_encryptor(self, iv: &[u8]) -> CryptoResult<impl StreamCipher + 'static> {
        new_cfb(self, iv, false)
    }

    fn to_cfb_decryptor(self, iv: &[u8]) -> CryptoResult<impl StreamCipher + 'static> {
        new_cfb(self, iv, true)
    }
}

impl<B: BlockCipher> StreamCipher for CfbImpl<B> {
    fn xor_key_stream(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
        let mut inout = inout;

        while !inout.is_empty() {
            if self.out_used == self.out.len() {
                self.out.copy_from_slice(&self.next);
                self.b.encrypt_block(&mut self.out);
                self.out_used = 0;
            }

            if self.decrypt {
                // We can precompute a larger segment of the
                // keystream on decryption. This will allow
                // larger batches for xor, and we should be
                // able to match CTR/OFB performance.
                let copy_len = copy(&mut self.next[self.out_used..], inout);
                let _ = copy_len; // Suppress unused variable warning
            }

            let n = xor_bytes(inout, &self.out[self.out_used..]);

            if !self.decrypt {
                let copy_len = copy(&mut self.next[self.out_used..], &inout[..n]);
                let _ = copy_len; // Suppress unused variable warning
            }

            inout = &mut inout[n..];
            self.out_used += n;
        }

        Ok(())
    }
}

/// CFB with 1- or 8-bit feedback, matching OpenSSL's `CFB1`/`CFB8` modes
/// (`CRYPTO_cfb128_1_encrypt` in `crypto/modes/cfb128.c`). The register is
/// shifted by `bits` per processed unit (one bit or one byte) and the
/// feedback is the ciphertext (encryption) or the received ciphertext
/// (decryption).
struct CfbBitsImpl<B: BlockCipher> {
    b: B,
    reg: Vec<u8>,
    bits: u8,
    decrypt: bool,
}

impl<B: BlockCipher> StreamCipher for CfbBitsImpl<B> {
    fn xor_key_stream(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
        let bs = self.b.block_size();
        let mut ks = vec![0u8; bs];
        for byte in inout.iter_mut() {
            if self.bits == 8 {
                ks.copy_from_slice(&self.reg);
                self.b.encrypt_block(&mut ks);
                let feedback = if self.decrypt { *byte } else { *byte ^ ks[0] };
                *byte ^= ks[0];
                self.reg.copy_within(1.., 0);
                self.reg[bs - 1] = feedback;
            } else {
                // One bit at a time, MSB first (packed bitstream).
                let mut out_byte = 0u8;
                for i in 0..8 {
                    ks.copy_from_slice(&self.reg);
                    self.b.encrypt_block(&mut ks);
                    let in_bit = (*byte >> (7 - i)) & 1;
                    let out_bit = in_bit ^ (ks[0] >> 7);
                    let feedback = if self.decrypt { in_bit } else { out_bit };
                    // reg = (reg << 1) | feedback
                    for j in 0..bs - 1 {
                        self.reg[j] = (self.reg[j] << 1) | (self.reg[j + 1] >> 7);
                    }
                    self.reg[bs - 1] = (self.reg[bs - 1] << 1) | feedback;
                    out_byte = (out_byte << 1) | out_bit;
                }
                *byte = out_byte;
            }
        }
        Ok(())
    }
}

/// Create a new CFB stream cipher
///
/// # Arguments
/// * `block` - The block cipher to use
/// * `iv` - The initialization vector, must be the same length as the block size
/// * `decrypt` - Whether this is for decryption (true) or encryption (false)
///
/// # Returns
/// A boxed StreamCipher implementation
///
/// # Panics
/// Panics if the IV length doesn't match the block size
fn new_cfb<B>(block: B, iv: &[u8], decrypt: bool) -> CryptoResult<impl StreamCipher>
where
    B: BlockCipher + 'static,
{
    let block_size = block.block_size();
    if iv.len() != block_size {
        return Err(CryptoError::InvalidIvSize(iv.len()));
    }

    let mut next = vec![0u8; block_size];
    copy(&mut next, iv);

    let cfb = CfbImpl {
        b: block,
        out: vec![0u8; block_size],
        next,
        out_used: block_size,
        decrypt,
    };

    Ok(cfb)
}

/// Create a new 1- or 8-bit feedback CFB stream cipher. `bits` must be 1 or 8.
fn new_cfb_bits<B>(block: B, iv: &[u8], bits: u8, decrypt: bool) -> CryptoResult<impl StreamCipher>
where
    B: BlockCipher + 'static,
{
    if bits != 1 && bits != 8 {
        return Err(CryptoError::InvalidParameterStr("cfb: bits must be 1 or 8"));
    }
    let block_size = block.block_size();
    if iv.len() != block_size {
        return Err(CryptoError::InvalidIvSize(iv.len()));
    }
    Ok(CfbBitsImpl {
        b: block,
        reg: iv.to_vec(),
        bits,
        decrypt,
    })
}
