mod generic;

#[cfg(all(feature = "asm", any(target_arch = "aarch64", target_arch = "x86_64")))]
mod asm;

use super::Md5;

pub(super) fn block(d: &mut Md5, p: &[u8]) {
    #[cfg(all(feature = "asm", any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        asm::block(d, p);
    }

    #[cfg(all(
        not(feature = "asm"),
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        generic::block_generic(d, p);
    }
}
