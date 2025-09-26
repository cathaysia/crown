//! ECB (Electronic Codebook) Mode implementation.
//!
//! ECB is the simplest encryption mode where each block of plaintext is encrypted
//! independently with the same key. While simple, ECB is not semantically secure
//! and should not be used for most applications as identical plaintext blocks
//! produce identical ciphertext blocks.

use crate::block::BlockCipher;
use crate::block::BlockCipherMarker;
use crate::error::CryptoResult;
use crate::modes::BlockMode;

/// ECB mode implementation
pub struct EcbImpl<B: BlockCipher> {
    cipher: B,
}

/// Trait for block ciphers that can be used with ECB mode
pub trait Ecb {
    fn to_ecb(self) -> CryptoResult<impl BlockMode + 'static>;
}

pub trait EcbGenericMarker {}
impl<T: BlockCipherMarker> EcbGenericMarker for T {}

impl<T> Ecb for T
where
    T: BlockCipher + EcbGenericMarker + 'static,
{
    fn to_ecb(self) -> CryptoResult<impl BlockMode + 'static> {
        Ok(EcbImpl { cipher: self })
    }
}

impl<B: BlockCipher> BlockMode for EcbImpl<B> {
    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    fn encrypt(&mut self, inout: &mut [u8]) {
        let block_size = self.cipher.block_size();
        assert!(inout.len() % block_size == 0);

        for chunk in inout.chunks_mut(block_size) {
            self.cipher.encrypt(chunk);
        }
    }

    fn decrypt(&mut self, inout: &mut [u8]) {
        let block_size = self.cipher.block_size();
        assert!(inout.len() % block_size == 0);

        for chunk in inout.chunks_mut(block_size) {
            self.cipher.decrypt(chunk);
        }
    }
}
