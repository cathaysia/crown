use crate::{
    cipher::{marker::BlockCipherMarker, BlockCipher, BlockMode},
    subtle::xor::{xor_bytes, xor_bytes_self},
};

use super::Cbc;

/// Trait for ciphers that have optimized CBC decryption implementation
pub trait CbcDecAble<B: BlockCipher> {
    /// Creates a new CBC decrypter
    ///
    /// # Panics
    ///
    /// Panics if the IV length doesn't match the block size
    fn to_cbc_dec(self, iv: &[u8]) -> impl BlockMode;
}

pub trait CbcDecAbleMarker {}
impl<T: BlockCipherMarker> CbcDecAbleMarker for T {}

impl<B: BlockCipher + CbcDecAbleMarker + 'static> CbcDecAble<B> for B {
    fn to_cbc_dec(self, iv: &[u8]) -> impl BlockMode {
        CbcDecrypter(Cbc::new(self, iv))
    }
}

impl CbcDecAble<crate::aes::Aes> for crate::aes::Aes {
    fn to_cbc_dec(self, iv: &[u8]) -> impl BlockMode {
        crate::aes::cbc::CBCDecrypter::new(self, iv.try_into().unwrap())
    }
}

/// CBC decrypter
pub struct CbcDecrypter<B: BlockCipher>(Cbc<B>);

impl<B: BlockCipher> BlockMode for CbcDecrypter<B> {
    fn block_size(&self) -> usize {
        self.0.block_size
    }

    fn crypt_blocks(mut self, inout: &mut [u8]) {
        if inout.len() % self.0.block_size != 0 {
            panic!("crypto/cipher: input not full blocks");
        }

        if inout.is_empty() {
            return;
        }

        let block_size = self.0.block_size;

        // For each block, we need to xor the decrypted data with the previous block's ciphertext (the iv).
        // To avoid making a copy each time, we loop over the blocks BACKWARDS.
        let mut end = inout.len();
        let mut start = end - block_size;

        // Copy the last block of ciphertext in preparation as the new iv
        self.0.tmp[..block_size].copy_from_slice(&inout[start..end]);

        // Loop over all but the first block
        while start > 0 {
            let prev = start - block_size;

            self.0.b.decrypt(&mut inout[start..end]);
            xor_bytes_self(&mut inout[start..end]);

            end = start;
            start = prev;
        }

        // The first block is special because it uses the saved iv
        self.0.b.decrypt(&mut inout[start..end]);
        xor_bytes(&mut inout[start..end], &self.0.iv);

        // Set the new iv to the first block we copied earlier
        std::mem::swap(&mut self.0.iv, &mut self.0.tmp);
    }
}

impl<B: BlockCipher> CbcDecrypter<B> {
    pub fn set_iv(&mut self, iv: &[u8]) {
        if iv.len() != self.0.iv.len() {
            panic!("cipher: incorrect length IV");
        }
        self.0.iv.copy_from_slice(iv);
    }
}
