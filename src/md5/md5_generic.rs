// #![cfg(not(any(target_arch = "aarch64")))]

use crate::md5::md5block::block_generic;
use crate::md5::Md5;

pub(super) fn block(d: &mut Md5, p: &[u8]) {
    block_generic(d, p);
}
