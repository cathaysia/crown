//! whirlpool assembly optimized block implementation

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/whirlpool/x86_64.ts"),
    options(att_syntax)
);

extern "C" {
    /// Assembly function for Whirlpool block processing on x86_64
    ///
    /// # Parameters
    /// - `state`: Pointer to Whirlpool state (8 u64 values: h0..h7)
    /// - `data`: Pointer to input data blocks
    /// - `num_blocks`: Number of 64-byte blocks to process
    fn whirlpool_block(state: *mut u64, data: *const u8, num_blocks: usize);
}

/// Process Whirlpool blocks using x86_64 assembly optimization
pub(super) fn block(h: &mut [u64; 8], p: &[u8]) {
    let num_blocks = p.len() / 64;
    if num_blocks == 0 {
        return;
    }

    unsafe {
        whirlpool_block(h.as_mut_ptr(), p.as_ptr(), num_blocks);
    }
}
