#[cfg(not(any(
    all(feature = "asm", target_arch = "x86_64"),
    crown_aarch64_asm,
    crown_riscv64_asm
)))]
use super::block::block_generic;
use super::*;
use crate::error::CryptoResult;

impl<const N: usize> Sha512<N> {
    pub(crate) fn block(&mut self, p: &[u8]) -> CryptoResult<()> {
        #[cfg(any(
            all(feature = "asm", target_arch = "x86_64"),
            crown_aarch64_asm,
            crown_riscv64_asm
        ))]
        {
            // riscv64 has only the vector body; without Zvkb/Zvknhb or with
            // VLEN < 128 the portable implementation stays in charge, like
            // the `sha_riscv.c` wrapper.
            #[cfg(crown_riscv64_asm)]
            if !super::block::asm::supported() {
                return super::block::block_generic(self, p);
            }
            super::block::asm::block(self, p)
        }

        #[cfg(not(any(
            all(feature = "asm", target_arch = "x86_64"),
            crown_aarch64_asm,
            crown_riscv64_asm
        )))]
        {
            block_generic(self, p)
        }
    }
}
