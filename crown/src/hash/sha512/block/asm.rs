//! sha512 assembly optimized SHA-512 block implementation

use super::super::Sha512;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha512/block/x86_64.ts"),
    options(att_syntax)
);

extern "C" {
    /// Assembly function for SHA-512 block processing on x86_64
    ///
    /// # Parameters
    /// - `state`: Pointer to SHA-512 state (8 u64 values: h0..h7)
    /// - `data`: Pointer to input data blocks
    /// - `num_blocks`: Number of 128-byte blocks to process
    fn sha512_block_data_order(state: *mut u64, data: *const u8, num_blocks: u32);
}

/// Process SHA-512 blocks using x86_64 assembly optimization
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

    unsafe {
        sha512_block_data_order(d.h.as_mut_ptr(), p.as_ptr(), num_blocks as u32);
    }

    Ok(())
}

use crate::error::CryptoResult;
