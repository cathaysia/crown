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
                self.b.encrypt(&mut self.out);
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
