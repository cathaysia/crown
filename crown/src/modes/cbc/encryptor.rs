use crate::{
    block::{BlockCipher, BlockCipherMarker},
    modes::BlockMode,
    utils::subtle::xor::xor_bytes,
};

use super::CbcImpl;

/// Trait for ciphers that have optimized CBC encryption implementation
pub trait CbcEncryptor<B> {
    /// Creates a new CBC encryptor
    ///
    /// # Panics
    ///
    /// Panics if the IV length doesn't match the block size
    fn to_cbc_enc(self, iv: &[u8]) -> impl BlockMode + 'static;
}

pub trait CbcEncryptorMarker {}
impl<T: BlockCipherMarker> CbcEncryptorMarker for T {}

/// CBC encryptor
struct CbcEncryptorImpl<B: BlockCipher>(CbcImpl<B>);

impl CbcEncryptor<crate::block::aes::Aes> for crate::block::aes::Aes {
    fn to_cbc_enc(self, iv: &[u8]) -> impl BlockMode + 'static {
        crate::block::aes::cbc::CBCEncryptor::new(self, iv.try_into().unwrap())
    }
}

impl<B: BlockCipher + CbcEncryptorMarker + 'static> CbcEncryptor<B> for B {
    fn to_cbc_enc(self, iv: &[u8]) -> impl BlockMode + 'static {
        if iv.len() != self.block_size() {
            panic!(
                "cipher.NewCBCEncrypter: IV length must equal block size: {}",
                self.block_size()
            );
        }

        CbcEncryptorImpl(CbcImpl::new(self, iv))
    }
}

impl<B: BlockCipher> BlockMode for CbcEncryptorImpl<B> {
    fn block_size(&self) -> usize {
        self.0.block_size
    }

    fn encrypt(&mut self, inout: &mut [u8]) {
        if inout.len() % self.0.block_size != 0 {
            panic!("crypto/cipher: input not full blocks");
        }

        let mut iv = self.0.iv.clone();
        let dst_chunks = inout.chunks_exact_mut(self.0.block_size);

        for dst_block in dst_chunks {
            // Write the xor to dst, then encrypt in place
            xor_bytes(dst_block, &iv);
            self.0.b.encrypt_block(dst_block);

            // Move to the next block with this block as the next iv
            iv.copy_from_slice(dst_block);
        }

        // Save the iv for the next CryptBlocks call
        self.0.iv.copy_from_slice(&iv);
    }
    fn decrypt(&mut self, _inout: &mut [u8]) {
        todo!()
    }
}
