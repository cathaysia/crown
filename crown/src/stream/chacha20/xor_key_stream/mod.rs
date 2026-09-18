mod generic;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
mod asm;
