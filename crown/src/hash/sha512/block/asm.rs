//! SHA-512 block transform, backed by the OpenSSL assembly
//! (sha512-x86_64.pl / sha512-armv8.pl, SHA-512 mode).

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

extern "C" {
    /// Assembly function for SHA-512 block processing
    ///
    /// # Parameters
    /// - `state`: Pointer to SHA-512 state (8 u64 values: h0..h7)
    /// - `data`: Pointer to input data blocks
    /// - `num_blocks`: Number of 128-byte blocks to process
    fn sha512_block_data_order(state: *mut u64, data: *const u8, num_blocks: u32);
}

/// Process SHA-512 blocks using the assembly implementation.
///
/// Both bodies dispatch internally: x86_64 on `OPENSSL_ia32cap_P`, aarch64 on
/// `OPENSSL_armcap_P`, which is published here first.
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
        sha512_block_data_order(d.h.as_mut_ptr(), p.as_ptr(), num_blocks as u32);
    }

    Ok(())
}

use crate::error::CryptoResult;
