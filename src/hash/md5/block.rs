mod generic;

#[cfg(target_arch = "aarch64")]
mod aarch64;

use super::Md5;

pub(super) fn block(d: &mut Md5, p: &[u8]) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::block(d, p);
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        generic::block_generic(d, p);
    }
}
