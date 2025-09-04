use crate::{
    cipher::{marker::BlockCipherMarker, BlockCipher, BlockMode},
    utils::subtle::xor::xor_bytes,
};

use super::Cbc;

/// Trait for ciphers that have optimized CBC encryption implementation
pub trait CbcEncAble<B> {
    /// Creates a new CBC encryptor
    ///
    /// # Panics
    ///
    /// Panics if the IV length doesn't match the block size
    fn to_cbc_enc(self, iv: &[u8]) -> impl BlockMode;
}

pub trait CbcEncAbleMarker {}
impl<T: BlockCipherMarker> CbcEncAbleMarker for T {}

/// CBC encryptor
pub struct CbcEncrypter<B: BlockCipher>(Cbc<B>);

impl<B: BlockCipher> CbcEncrypter<B> {
    pub fn set_iv(&mut self, iv: &[u8]) {
        if iv.len() != self.0.iv.len() {
            panic!("cipher: incorrect length IV");
        }
        self.0.iv.copy_from_slice(iv);
    }
}

impl CbcEncAble<crate::aes::Aes> for crate::aes::Aes {
    fn to_cbc_enc(self, iv: &[u8]) -> impl BlockMode {
        crate::aes::cbc::CBCEncryptor::new(self, iv.try_into().unwrap())
    }
}

impl<B: BlockCipher + CbcEncAbleMarker + 'static> CbcEncAble<B> for B {
    fn to_cbc_enc(self, iv: &[u8]) -> impl BlockMode {
        if iv.len() != self.block_size() {
            panic!("cipher.NewCBCEncrypter: IV length must equal block size");
        }

        CbcEncrypter(Cbc::new(self, iv))
    }
}

impl<B: BlockCipher> BlockMode for CbcEncrypter<B> {
    fn block_size(&self) -> usize {
        self.0.block_size
    }

    fn crypt_blocks(mut self, inout: &mut [u8]) {
        if inout.len() % self.0.block_size != 0 {
            panic!("crypto/cipher: input not full blocks");
        }

        let mut iv = self.0.iv.clone();
        let dst_chunks = inout.chunks_exact_mut(self.0.block_size);

        for dst_block in dst_chunks {
            // Write the xor to dst, then encrypt in place
            xor_bytes(dst_block, &iv);
            self.0.b.encrypt(dst_block);

            // Move to the next block with this block as the next iv
            iv.copy_from_slice(dst_block);
        }

        // Save the iv for the next CryptBlocks call
        self.0.iv.copy_from_slice(&iv);
    }
}
