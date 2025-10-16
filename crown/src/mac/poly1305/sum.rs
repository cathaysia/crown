mod generic;
pub use generic::*;

#[cfg(all(feature = "asm", any(target_arch = "aarch64", target_arch = "x86_64")))]
mod asm;
#[cfg(all(feature = "asm", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub use asm::*;

#[cfg(all(feature = "asm", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub type Mac = MacAarch64;

#[cfg(any(
    not(feature = "asm"),
    not(any(target_arch = "aarch64", target_arch = "x86_64"))
))]
pub(crate) type Mac = MacGeneric;
