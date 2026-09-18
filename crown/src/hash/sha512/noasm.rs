#[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
use super::block::block_generic;
use super::*;
use crate::error::CryptoResult;

impl<const N: usize> Sha512<N> {
    pub(crate) fn block(&mut self, p: &[u8]) -> CryptoResult<()> {
        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        {
            super::block::asm::block(self, p)
        }

        #[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
        {
            block_generic(self, p)
        }
    }
}
