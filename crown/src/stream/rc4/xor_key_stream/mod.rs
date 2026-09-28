#[cfg(all(feature = "asm", target_arch = "x86_64"))]
mod asm;
#[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
mod generic;
