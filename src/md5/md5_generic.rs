// #![cfg(not(any(target_arch = "aarch64")))]

use crate::md5::md5block::block_generic;
use crate::md5::Digest;

pub(super) const HAVE_ASM: bool = false;

pub(super) fn block(d: &mut Digest, p: &[u8]) {
    block_generic(d, p);
}
