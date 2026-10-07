#[cfg(any(
    all(feature = "asm", target_arch = "x86_64"),
    crown_aarch64_asm,
    crown_riscv64_asm
))]
mod asm;

use super::Sha256;

pub(super) fn block<const N: usize, const IS_224: bool>(d: &mut Sha256<N, IS_224>, p: &[u8]) {
    #[cfg(any(
        all(feature = "asm", target_arch = "x86_64"),
        crown_aarch64_asm,
        crown_riscv64_asm
    ))]
    {
        // riscv64 has only the vector body, so a CPU without Zvkb/Zvknha/b
        // or with VLEN < 128 stays on the portable implementation, exactly
        // like the `sha_riscv.c` wrapper.
        #[cfg(crown_riscv64_asm)]
        if !asm::supported() {
            super::generic::block_generic(d, p);
            return;
        }
        asm::block(d, p);
    }

    #[cfg(not(any(
        all(feature = "asm", target_arch = "x86_64"),
        crown_aarch64_asm,
        crown_riscv64_asm
    )))]
    {
        super::generic::block_generic(d, p);
    }
}
