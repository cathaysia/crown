//! AArch64 assembly optimized MD5 implementation

use super::Md5;

extern "C" {
    /// Assembly function for MD5 block processing on AArch64
    ///
    /// # Parameters
    /// - `state`: Pointer to MD5 state (4 u32 values: A, B, C, D)
    /// - `data`: Pointer to input data blocks
    /// - `num_blocks`: Number of 64-byte blocks to process
    fn ossl_md5_block_asm_data_order(state: *mut u32, data: *const u8, num_blocks: u32);
}

/// Process MD5 blocks using AArch64 assembly optimization
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

    unsafe {
        ossl_md5_block_asm_data_order(d.s.as_mut_ptr(), p.as_ptr(), num_blocks as u32);
    }

    // If there are remaining bytes, they should be handled by the caller
    // as partial blocks are handled in the main MD5 implementation
}
