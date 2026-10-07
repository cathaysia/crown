mod generic;

#[cfg(any(
    all(feature = "asm", target_arch = "x86_64"),
    crown_aarch64_asm,
    crown_riscv64_asm
))]
mod asm;
