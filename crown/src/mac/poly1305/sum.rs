mod generic;
pub use generic::*;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
mod x86_64;
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub use x86_64::*;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) type Mac = MacAsm;
#[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
pub(crate) type Mac = MacGeneric;
