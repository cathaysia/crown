mod generic;

#[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
mod asm;

use super::{Sha1, CHUNK};

pub(super) fn block(d: &mut Sha1, p: &[u8]) {
    #[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
    {
        asm::block(d, p);
    }

    #[cfg(not(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm)))]
    {
        generic::block_generic(d, p);
    }
}
