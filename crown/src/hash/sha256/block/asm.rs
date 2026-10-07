//! SHA-256 block transform, backed by the OpenSSL assembly
//! (sha512-x86_64.pl / sha512-armv8.pl, SHA-256 mode;
//! sha256-riscv64-zvkb-zvknha_or_zvknhb.pl on riscv64).

use super::super::Sha256;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha256/block/x86_64.ts"),
    options(att_syntax)
);

#[cfg(crown_aarch64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha256/block/aarch64.ts"),
    // The aarch64 operands carry `{v0.16b}`-style lane braces.
    options(raw)
);

#[cfg(crown_riscv64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha256/block/riscv64.ts"),
    // The comments carry `{f,e,b,a}`-style state-vector runs.
    options(raw)
);

extern "C" {
    /// Assembly function for SHA-256 block processing
    ///
    /// # Parameters
    /// - `state`: Pointer to SHA-256 state (8 u32 values: h0..h7)
    /// - `data`: Pointer to input data blocks
    /// - `num_blocks`: Number of 64-byte blocks to process
    #[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
    fn sha256_block_data_order(state: *mut u32, data: *const u8, num_blocks: u32);

    /// The `Zvkb + Zvknha/Zvknhb` vector body. `sha_riscv.c` selects it from
    /// the same capability test as [`supported`]; it takes the block count as
    /// a `size_t` and reads and writes only the 8 state words at `state`.
    #[cfg(crown_riscv64_asm)]
    fn sha256_block_data_order_zvkb_zvknha_or_zvknhb(
        state: *mut u32,
        data: *const u8,
        num_blocks: usize,
    );
}

/// `sha_riscv.c`: the vector body needs `Zvkb` (`Zvbb` counts as a superset),
/// `Zvknha` or `Zvknhb`, and a vector register of at least 128 bits.
#[cfg(crown_riscv64_asm)]
pub(super) fn supported() -> bool {
    use crate::utils::cpuid::{has_zvkb, riscv_vlen, riscvcap, RISCV_ZVKNHA, RISCV_ZVKNHB};
    has_zvkb() && riscvcap() & (RISCV_ZVKNHA | RISCV_ZVKNHB) != 0 && riscv_vlen() >= 128
}

/// Process SHA-256 blocks using the assembly implementation.
///
/// The x86_64 and aarch64 bodies dispatch internally (on
/// `OPENSSL_ia32cap_P` / `OPENSSL_armcap_P`, the latter published here
/// first); the riscv64 vector body is only correct on a CPU that passes
/// [`supported`], which the caller checks.
pub(super) fn block<const N: usize, const IS_224: bool>(d: &mut Sha256<N, IS_224>, p: &[u8]) {
    let len = p.len();
    if len == 0 {
        return;
    }

    // Ensure we only process complete 64-byte blocks
    let num_blocks = len / 64;
    if num_blocks == 0 {
        return;
    }

    #[cfg(crown_aarch64_asm)]
    crate::utils::cpuid::armcap();

    unsafe {
        #[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
        sha256_block_data_order(d.h.as_mut_ptr(), p.as_ptr(), num_blocks as u32);
        #[cfg(crown_riscv64_asm)]
        sha256_block_data_order_zvkb_zvknha_or_zvknhb(d.h.as_mut_ptr(), p.as_ptr(), num_blocks);
    }
}
