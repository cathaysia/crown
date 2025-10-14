use crate::{
    block::{BlockCipher, BlockCipherMarker},
    modes::BlockMode,
    utils::{copy, erase_ownership, subtle::xor::xor_bytes},
};

use super::CbcImpl;

/// Trait for ciphers that have optimized CBC decryption implementation
pub trait CbcDecryptor<B: BlockCipher> {
    /// Creates a new CBC decrypter
    ///
    /// # Panics
    ///
    /// Panics if the IV length doesn't match the block size
    fn to_cbc_dec(self, iv: &[u8]) -> impl BlockMode + 'static;
}

pub trait CbcDecryptorMarker {}
impl<T: BlockCipherMarker> CbcDecryptorMarker for T {}

impl<B: BlockCipher + CbcDecryptorMarker + 'static> CbcDecryptor<B> for B {
    fn to_cbc_dec(self, iv: &[u8]) -> impl BlockMode + 'static {
        CbcDecryptorImpl(CbcImpl::new(self, iv))
    }
}

impl CbcDecryptor<crate::block::aes::Aes> for crate::block::aes::Aes {
    fn to_cbc_dec(self, iv: &[u8]) -> impl BlockMode + 'static {
        crate::block::aes::cbc::CBCDecrypter::new(self, iv.try_into().unwrap())
    }
}

/// CBC decrypter
struct CbcDecryptorImpl<B: BlockCipher>(CbcImpl<B>);

impl<B: BlockCipher> BlockMode for CbcDecryptorImpl<B> {
    fn block_size(&self) -> usize {
        self.0.block_size
    }

    fn encrypt(&mut self, inout: &mut [u8]) {
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
        copy(&mut self.0.tmp, &inout[start..end]);

        // Loop over all but the first block
        while start > 0 {
            let prev = start - block_size;

            self.0.b.decrypt_block(&mut inout[start..end]);
            let src = unsafe { erase_ownership(&*inout) };
            xor_bytes(&mut inout[start..end], &src[prev..start]);

            end = start;
            start = prev;
        }

        // The first block is special because it uses the saved iv
        self.0.b.decrypt_block(&mut inout[start..end]);
        xor_bytes(&mut inout[start..end], &self.0.iv);

        // Set the new iv to the first block we copied earlier
        core::mem::swap(&mut self.0.iv, &mut self.0.tmp);
    }

    fn decrypt(&mut self, _inout: &mut [u8]) {
        unreachable!()
    }
}
