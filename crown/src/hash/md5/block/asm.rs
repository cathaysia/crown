//! MD5 block transform, backed by the OpenSSL assembly (md5-x86_64.pl /
//! md5-aarch64.pl).

use super::Md5;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/md5/block/x86_64.ts"),
    options(att_syntax)
);

#[cfg(crown_aarch64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/md5/block/aarch64.ts"),
    // The aarch64 operands carry `{v0.16b}`-style lane braces.
    options(raw)
);

extern "C" {
    /// Assembly function for MD5 block processing
    ///
    /// # Parameters
    /// - `state`: Pointer to MD5 state (4 u32 values: A, B, C, D)
    /// - `data`: Pointer to input data blocks
    /// - `num_blocks`: Number of 64-byte blocks to process
    fn ossl_md5_block_asm_data_order(state: *mut u32, data: *const u8, num_blocks: u32);
}

/// Process MD5 blocks using the assembly implementation.
///
/// The aarch64 body is a NEON implementation without a feature test of its
/// own, so the capability word is published first.
pub(super) fn block(d: &mut Md5, p: &[u8]) {
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
        ossl_md5_block_asm_data_order(d.s.as_mut_ptr(), p.as_ptr(), num_blocks as u32);
    }
}
