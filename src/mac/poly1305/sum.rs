mod generic;
pub use generic::*;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
mod asm;
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub use asm::*;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub type Mac = MacAarch64;

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(crate) type Mac = MacGeneric;
