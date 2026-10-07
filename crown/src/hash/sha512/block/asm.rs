//! SHA-512 block transform, backed by the OpenSSL assembly
//! (sha512-x86_64.pl / sha512-armv8.pl, SHA-512 mode;
//! sha512-riscv64-zvkb-zvknhb.pl on riscv64).

use super::super::Sha512;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha512/block/x86_64.ts"),
    options(att_syntax)
);

#[cfg(crown_aarch64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha512/block/aarch64.ts"),
    // The aarch64 operands carry `{v0.16b}`-style lane braces.
    options(raw)
);

#[cfg(crown_riscv64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha512/block/riscv64.ts"),
    // The comments carry `{f,e,b,a}`-style state-vector runs.
    options(raw)
);

extern "C" {
    /// Assembly function for SHA-512 block processing
    ///
    /// # Parameters
    /// - `state`: Pointer to SHA-512 state (8 u64 values: h0..h7)
    /// - `data`: Pointer to input data blocks
    /// - `num_blocks`: Number of 128-byte blocks to process
    #[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
    fn sha512_block_data_order(state: *mut u64, data: *const u8, num_blocks: u32);

    /// The `Zvkb + Zvknhb` vector body. `sha_riscv.c` selects it from the
    /// same capability test as [`supported`]; the state is addressed through
    /// an indexed load/store of the 64 bytes at `state`.
    #[cfg(crown_riscv64_asm)]
    fn sha512_block_data_order_zvkb_zvknhb(state: *mut u64, data: *const u8, num_blocks: usize);
}

/// `sha_riscv.c`: the vector body needs `Zvkb` (`Zvbb` counts as a superset),
/// `Zvknhb`, and a vector register of at least 128 bits.
#[cfg(crown_riscv64_asm)]
pub(crate) fn supported() -> bool {
    use crate::utils::cpuid::{has_zvkb, riscv_vlen, riscvcap, RISCV_ZVKNHB};
    has_zvkb() && riscvcap() & RISCV_ZVKNHB != 0 && riscv_vlen() >= 128
}

/// Process SHA-512 blocks using the assembly implementation.
///
/// The x86_64 and aarch64 bodies dispatch internally (on
/// `OPENSSL_ia32cap_P` / `OPENSSL_armcap_P`, the latter published here
/// first); the riscv64 vector body is only correct on a CPU that passes
/// [`supported`], which the caller checks.
pub(crate) fn block<const N: usize>(d: &mut Sha512<N>, p: &[u8]) -> CryptoResult<()> {
    let len = p.len();
    if len == 0 {
        return Ok(());
    }

    // Ensure we only process complete 128-byte blocks
    let num_blocks = len / 128;
    if num_blocks == 0 {
        return Ok(());
    }

    #[cfg(crown_aarch64_asm)]
    crate::utils::cpuid::armcap();

    unsafe {
        #[cfg(any(all(feature = "asm", target_arch = "x86_64"), crown_aarch64_asm))]
        sha512_block_data_order(d.h.as_mut_ptr(), p.as_ptr(), num_blocks as u32);
        #[cfg(crown_riscv64_asm)]
        sha512_block_data_order_zvkb_zvknhb(d.h.as_mut_ptr(), p.as_ptr(), num_blocks);
    }

    Ok(())
}

use crate::error::CryptoResult;
