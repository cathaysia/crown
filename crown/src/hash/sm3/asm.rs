//! SM3 block transform, backed by the OpenSSL SM3 extension assembly
//! (sm3-x86_64.pl / sm3-armv8.pl / sm3-riscv64-zvksh.pl).

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sm3/x86_64.ts"),
    options(att_syntax)
);

#[cfg(crown_aarch64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sm3/aarch64.ts"),
    // The aarch64 operands carry `{v0.16b}`-style lane braces.
    options(raw)
);

#[cfg(crown_riscv64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sm3/riscv64.ts"),
    // The comments carry `{w7, ..., w0}`-style word runs.
    options(raw)
);

extern "C" {
    /// Assembly function for SM3 block processing
    ///
    /// # Parameters
    /// - `state`: Pointer to the 8 u32 state words (A..H, in memory order)
    /// - `data`: Pointer to the input data blocks
    /// - `num_blocks`: Number of 64-byte blocks to process
    #[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
    fn ossl_hwsm3_block_data_order(state: *mut u32, data: *const u8, num_blocks: usize);

    /// The `Zvkb + Zvksh` vector body; `sm3_riscv.c` selects it from the same
    /// capability test as [`sm3_supported`]. It reads and writes the state
    /// words at offset 0 of the context it is handed.
    #[cfg(crown_riscv64_asm)]
    fn ossl_hwsm3_block_data_order_zvksh(state: *mut u32, data: *const u8, num_blocks: usize);
}

/// SM3-NI is enumerated in CPUID(EAX=7, ECX=1).EBX bit 0, which the cpuid
/// setup stores in ia32cap[7]; aarch64 uses the ARMv8.2 SM3 crypto extension.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn sm3_supported() -> bool {
    crate::utils::cpuid::ia32cap(7) & 1 != 0
}

/// aarch64 counterpart of `sm3_supported`.
#[cfg(crown_aarch64_asm)]
pub fn sm3_supported() -> bool {
    crate::utils::cpuid::armcap() & crate::utils::cpuid::ARMV8_SM3 != 0
}

/// riscv64 counterpart: `sm3_riscv.c` wants `Zvkb + Zvksh` and VLEN >= 128.
#[cfg(crown_riscv64_asm)]
pub fn sm3_supported() -> bool {
    use crate::utils::cpuid::{has_zvkb, riscv_vlen, riscvcap, RISCV_ZVKSH};
    has_zvkb() && riscvcap() & RISCV_ZVKSH != 0 && riscv_vlen() >= 128
}

/// Process SM3 blocks using the SM3 extension assembly, mirroring
/// block_data_order's scalar loop over complete blocks.
pub fn block_data_order(d: &mut super::Sm3, data: &[u8], num_blocks: usize) {
    let mut state = [d.a, d.b, d.c, d.d, d.e, d.f, d.g, d.h];
    unsafe {
        #[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
        ossl_hwsm3_block_data_order(state.as_mut_ptr(), data.as_ptr(), num_blocks);
        #[cfg(crown_riscv64_asm)]
        ossl_hwsm3_block_data_order_zvksh(state.as_mut_ptr(), data.as_ptr(), num_blocks);
    }
    [d.a, d.b, d.c, d.d, d.e, d.f, d.g, d.h] = state;
}
