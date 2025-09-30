#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
mod asm;

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
mod generic;
