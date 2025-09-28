mod generic;
pub use generic::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(target_arch = "aarch64")]
pub type Mac = MacAarch64;

#[cfg(not(target_arch = "aarch64"))]
pub type Mac = MacGeneric;
