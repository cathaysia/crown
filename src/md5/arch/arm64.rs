#![cfg(target_arch = "aarch64")]

use std::arch::asm;

use derive::jinja_file;

use crate::md5::Digest;

pub fn block(_dig: &mut Digest, _p: &[u8]) {
    unsafe { asm!(jinja_file!("./src/md5/arch/arm64.S")) }
}
