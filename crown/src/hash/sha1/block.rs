mod generic;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
mod asm;

use super::{Sha1, CHUNK};

pub(super) fn block(d: &mut Sha1, p: &[u8]) {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        asm::block(d, p);
    }

    #[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
    {
        generic::block_generic(d, p);
    }
}
