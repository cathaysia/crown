//! sha256 assembly optimized SHA-256 block implementation

use super::super::Sha256;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha256/block/x86_64.ts"),
    options(att_syntax)
);

extern "C" {
    /// Assembly function for SHA-256 block processing on x86_64
    ///
    /// # Parameters
    /// - `state`: Pointer to SHA-256 state (8 u32 values: h0..h7)
    /// - `data`: Pointer to input data blocks
    /// - `num_blocks`: Number of 64-byte blocks to process
    fn sha256_block_data_order(state: *mut u32, data: *const u8, num_blocks: u32);
}

/// Process SHA-256 blocks using x86_64 assembly optimization
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

    unsafe {
        sha256_block_data_order(d.h.as_mut_ptr(), p.as_ptr(), num_blocks as u32);
    }
}
