#[cfg(all(feature = "asm", target_arch = "x86_64"))]
mod asm;

use super::Sha256;

pub(super) fn block<const N: usize, const IS_224: bool>(d: &mut Sha256<N, IS_224>, p: &[u8]) {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        asm::block(d, p);
    }

    #[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
    {
        super::generic::block_generic(d, p);
    }
}
