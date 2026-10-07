#[cfg(not(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm)))]
use super::block::block_generic;
use super::*;
use crate::error::CryptoResult;

impl<const N: usize> Sha512<N> {
    pub(crate) fn block(&mut self, p: &[u8]) -> CryptoResult<()> {
        #[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
        {
            super::block::asm::block(self, p)
        }

        #[cfg(not(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm)))]
        {
            block_generic(self, p)
        }
    }
}
