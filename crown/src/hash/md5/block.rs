mod generic;

#[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
mod asm;

use super::Md5;

pub(super) fn block(d: &mut Md5, p: &[u8]) {
    #[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
    {
        asm::block(d, p);
    }

    #[cfg(not(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm)))]
    {
        generic::block_generic(d, p);
    }
}
