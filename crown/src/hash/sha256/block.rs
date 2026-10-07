#[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
mod asm;

use super::Sha256;

pub(super) fn block<const N: usize, const IS_224: bool>(d: &mut Sha256<N, IS_224>, p: &[u8]) {
    #[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
    {
        asm::block(d, p);
    }

    #[cfg(not(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm)))]
    {
        super::generic::block_generic(d, p);
    }
}
