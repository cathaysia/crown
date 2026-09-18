//! Keccak-1600 assembly implementation.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha3/x86_64.ts"),
    options(att_syntax)
);

extern "C" {
    /// Assembly function for the Keccak-f[1600] permutation on x86_64
    ///
    /// # Parameters
    /// - `state`: Pointer to the 200-byte Keccak state
    fn KeccakF1600(state: *mut u8);
}

/// Permute the Keccak state using x86_64 assembly optimization
pub fn keccak_f1600(da: &mut [u8; 200]) {
    unsafe {
        KeccakF1600(da.as_mut_ptr());
    }
}
