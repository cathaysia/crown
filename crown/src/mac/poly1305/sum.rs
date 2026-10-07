mod generic;
pub use generic::*;

#[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
mod asm;
#[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
pub use asm::*;

#[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
pub(crate) type Mac = MacAsm;
#[cfg(not(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm)))]
pub(crate) type Mac = MacGeneric;
