#![cfg(any(target_arch = "aarch64"))]

mod arm64;
pub(super) use arm64::block;

pub(super) const HAVE_ASM: bool = true;
