#[cfg(all(feature = "asm", any(target_arch = "aarch64", target_arch = "x86_64")))]
mod asm;

#[cfg(any(
    not(feature = "asm"),
    not(any(target_arch = "aarch64", target_arch = "x86_64"))
))]
mod generic;
