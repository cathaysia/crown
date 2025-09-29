#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(not(target_arch = "aarch64"))]
mod generic;
