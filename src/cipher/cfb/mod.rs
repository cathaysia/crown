//! CFB (Cipher Feedback) Mode implementation.
//!

use super::*;
use crate::cipher::marker::BlockCipherMarker;
use crate::cipher::StreamCipher;
use crate::error::{CryptoError, CryptoResult};
use crate::subtle::xor::xor_bytes;
use crate::utils::{copy, inexact_overlap};

#[cfg(test)]
mod tests;

/// CFB stream cipher implementation
pub struct Cfb<B: BlockCipher> {
    b: B,
    next: Vec<u8>,
    out: Vec<u8>,
    out_used: usize,
    decrypt: bool,
}

/// Trait for block ciphers that can be used with CFB mode
pub trait CfbAble {
    /// Create a new CFB encryptor with the given IV
    fn to_cfb_encrypter(self, iv: &[u8]) -> CryptoResult<impl StreamCipher>;

    /// Create a new CFB decrypter with the given IV
    fn to_cfb_decrypter(self, iv: &[u8]) -> CryptoResult<impl StreamCipher>;
}

/// Marker trait for types that can be used with CFB
pub trait CfbAbleMarker {}
impl<T: BlockCipherMarker> CfbAbleMarker for T {}

impl<T> CfbAble for T
where
    T: BlockCipher + CfbAbleMarker + 'static,
{
    fn to_cfb_encrypter(self, iv: &[u8]) -> CryptoResult<impl StreamCipher> {
        new_cfb(self, iv, false)
    }

    fn to_cfb_decrypter(self, iv: &[u8]) -> CryptoResult<impl StreamCipher> {
        new_cfb(self, iv, true)
    }
}

impl<B: BlockCipher> StreamCipher for Cfb<B> {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> CryptoResult<()> {
        if dst.len() < src.len() {
            panic!("crypto/cipher: output smaller than input");
        }

        if inexact_overlap(&dst[..src.len()], src) {
            panic!("crypto/cipher: invalid buffer overlap");
        }

        let mut dst = &mut dst[..src.len()];
        let mut src = src;

        while !src.is_empty() {
            if self.out_used == self.out.len() {
                self.out.copy_from_slice(&self.next);
                self.b.encrypt(&mut self.out);
                self.out_used = 0;
            }

            if self.decrypt {
                // We can precompute a larger segment of the
                // keystream on decryption. This will allow
                // larger batches for xor, and we should be
                // able to match CTR/OFB performance.
                let copy_len = copy(&mut self.next[self.out_used..], src);
                let _ = copy_len; // Suppress unused variable warning
            }

            let n = xor_bytes(dst, src, &self.out[self.out_used..]);

            if !self.decrypt {
                let copy_len = copy(&mut self.next[self.out_used..], &dst[..n]);
                let _ = copy_len; // Suppress unused variable warning
            }

            dst = &mut dst[n..];
            src = &src[n..];
            self.out_used += n;
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

    let cfb = Cfb {
        b: block,
        out: vec![0u8; block_size],
        next,
        out_used: block_size,
        decrypt,
    };

    Ok(cfb)
}

/// Create a new CFB encryptor
///
/// CFB mode is not authenticated, which generally enables active
/// attacks to manipulate and recover the plaintext. It is recommended that
/// applications use AEAD modes instead. The standard library implementation of
/// CFB is also unoptimized and not validated as part of the FIPS 140-3 module.
/// If an unauthenticated Stream mode is required, use CTR instead.
///
/// # Arguments
/// * `block` - The block cipher to use
/// * `iv` - The initialization vector, must be the same length as the block size
///
/// # Returns
/// A boxed StreamCipher implementation for encryption
///
/// # Errors
/// Returns an error if the IV length doesn't match the block size
pub fn new_cfb_encrypter<B>(block: B, iv: &[u8]) -> CryptoResult<impl StreamCipher>
where
    B: BlockCipher + 'static,
{
    new_cfb(block, iv, false)
}

/// Create a new CFB decrypter
///
/// CFB mode is not authenticated, which generally enables active
/// attacks to manipulate and recover the plaintext. It is recommended that
/// applications use AEAD modes instead. The standard library implementation of
/// CFB is also unoptimized and not validated as part of the FIPS 140-3 module.
/// If an unauthenticated Stream mode is required, use CTR instead.
///
/// # Arguments
/// * `block` - The block cipher to use
/// * `iv` - The initialization vector, must be the same length as the block size
///
/// # Returns
/// A boxed StreamCipher implementation for decryption
///
/// # Errors
/// Returns an error if the IV length doesn't match the block size
pub fn new_cfb_decrypter<B>(block: B, iv: &[u8]) -> CryptoResult<impl StreamCipher>
where
    B: BlockCipher + 'static,
{
    new_cfb(block, iv, true)
}
