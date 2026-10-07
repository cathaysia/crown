//! SHA-1 block transform, backed by the OpenSSL assembly
//! (sha1-x86_64.pl / sha1-armv8.pl).

use super::super::Sha1;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha1/block/x86_64.ts"),
    options(att_syntax)
);

#[cfg(crown_aarch64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha1/block/aarch64.ts"),
    // The aarch64 operands carry `{v0.16b}`-style lane braces.
    options(raw)
);

extern "C" {
    /// Assembly function for SHA-1 block processing
    ///
    /// # Parameters
    /// - `state`: Pointer to SHA-1 state (5 u32 values: h0..h4)
    /// - `data`: Pointer to input data blocks
    /// - `num_blocks`: Number of 64-byte blocks to process
    fn sha1_block_data_order(state: *mut u32, data: *const u8, num_blocks: u32);
}

/// Process SHA-1 blocks using the assembly implementation.
///
/// Both bodies dispatch internally: x86_64 on `OPENSSL_ia32cap_P`, aarch64 on
/// `OPENSSL_armcap_P`, which is published here first.
pub(super) fn block(d: &mut Sha1, p: &[u8]) {
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
        sha1_block_data_order(d.h.as_mut_ptr(), p.as_ptr(), num_blocks as u32);
    }
}
