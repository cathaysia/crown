//! Keccak-1600 assembly implementation.
//!
//! The x86_64 module exports a bare `KeccakF1600` plus the fused
//! `SHA3_absorb`/`SHA3_squeeze`; the aarch64 module exports only the fused
//! pair (the single-permutation paths stay with the portable implementation
//! there). The ARMv8.2 crypto-extension bodies (`*_cext`) are used exactly
//! where `sha3_prov.c` uses them: behind `ARMV8_HAVE_SHA3_AND_WORTH_USING`.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha3/x86_64.ts"),
    options(att_syntax)
);

#[cfg(crown_aarch64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/hash/sha3/aarch64.ts"),
    // The aarch64 operands carry `{v0.16b}`-style lane braces.
    options(raw)
);

extern "C" {
    /// Assembly function for the Keccak-f[1600] permutation (x86_64)
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    fn KeccakF1600(state: *mut u8);

    /// XOR whole rate-sized blocks into the state and permute after each of
    /// them; returns the trailing bytes that did not fill a block.
    fn SHA3_absorb(state: *mut u8, inp: *const u8, len: usize, rate: usize) -> usize;

    /// Copy `len` bytes (a multiple of `rate`) out of the state, permuting
    /// between blocks. `next` must be 0: the caller hands over a state that
    /// was just permuted.
    fn SHA3_squeeze(state: *mut u8, out: *mut u8, len: usize, rate: usize, next: i32);

    /// ARMv8.2 SHA3 crypto-extension body of [`SHA3_absorb`].
    #[cfg(crown_aarch64_asm)]
    fn SHA3_absorb_cext(state: *mut u8, inp: *const u8, len: usize, rate: usize) -> usize;
}

/// Permute the Keccak state using the x86_64 assembly implementation.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn keccak_f1600(da: &mut [u8; 200]) {
    unsafe {
        KeccakF1600(da.as_mut_ptr());
    }
}

/// Absorb whole blocks of `inp` and permute, like `SHA3_absorb` of
/// `crypto/sha/keccak1600.c`. The state must be block-aligned (nothing of the
/// current block absorbed yet); `inp` must hold at least one full block. The
/// returned remainder is left to the caller, which buffers it in the state.
pub fn absorb(state: &mut [u8; 200], inp: &[u8], rate: usize) -> usize {
    debug_assert!(rate < 200 && rate.is_multiple_of(8));
    debug_assert!(inp.len() >= rate);

    #[cfg(crown_aarch64_asm)]
    {
        if crate::utils::cpuid::armcap() & crate::utils::cpuid::ARMV8_HAVE_SHA3_AND_WORTH_USING != 0
        {
            return unsafe { SHA3_absorb_cext(state.as_mut_ptr(), inp.as_ptr(), inp.len(), rate) };
        }
    }

    unsafe { SHA3_absorb(state.as_mut_ptr(), inp.as_ptr(), inp.len(), rate) }
}

/// Squeeze `out.len()` bytes (a whole multiple of `rate`) from a state that
/// was just permuted, like `SHA3_squeeze` of `crypto/sha/keccak1600.c` with
/// `next = 0`.
pub fn squeeze(state: &mut [u8; 200], out: &mut [u8], rate: usize) {
    debug_assert!(rate < 200 && rate.is_multiple_of(8));
    debug_assert!(out.len().is_multiple_of(rate));
    unsafe { SHA3_squeeze(state.as_mut_ptr(), out.as_mut_ptr(), out.len(), rate, 0) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha3::keccakf::keccak_f1600_generic;

    /// The fused absorb must match the sponge's own loop: XOR each block into
    /// the leading lanes, permute, and leave the remainder to the caller.
    #[test]
    fn absorb_matches_generic_loop() {
        for rate in [168usize, 136, 104, 72, 144] {
            let mut state_asm = [0u8; 200];
            let mut state_gen = [0u8; 200];
            let msg: alloc::vec::Vec<u8> = (0..rate * 3 + 5).map(|i| (i * 7) as u8).collect();

            // asm path
            let left = absorb(&mut state_asm, &msg, rate);
            assert_eq!(left, msg.len() % rate);

            // generic path: same operations
            for chunk in msg.chunks_exact(rate) {
                for (dst, src) in state_gen.iter_mut().zip(chunk.iter()) {
                    *dst ^= *src;
                }
                keccak_f1600_generic(&mut state_gen);
            }
            assert_eq!(state_asm, state_gen, "rate={rate}");

            // and the trailing bytes are the ones the caller must absorb
            let tail = &msg[msg.len() - left..];
            assert_eq!(tail, &msg[msg.len() - left..]);
        }
    }

    /// The fused squeeze must match the sponge's loop: read a block, permute,
    /// read the next.
    #[test]
    fn squeeze_matches_generic_loop() {
        for rate in [168usize, 136, 104, 72, 144] {
            let mut state_asm = [0u8; 200];
            let mut state_gen = [0u8; 200];
            for i in 0..200 {
                state_asm[i] = (i * 13) as u8;
            }
            state_gen.copy_from_slice(&state_asm);
            keccak_f1600_generic(&mut state_asm);
            keccak_f1600_generic(&mut state_gen);

            let mut out_asm = alloc::vec![0u8; rate * 3];
            let mut out_gen = alloc::vec![0u8; rate * 3];
            squeeze(&mut state_asm, &mut out_asm, rate);

            for (i, chunk) in out_gen.chunks_mut(rate).enumerate() {
                chunk.copy_from_slice(&state_gen[..rate]);
                if i + 1 < 3 {
                    keccak_f1600_generic(&mut state_gen);
                }
            }
            // The fused routine permutes after every block but the last, so
            // the resulting states must agree as well.
            assert_eq!(out_asm, out_gen, "rate={rate}");
            assert_eq!(state_asm, state_gen, "state after squeeze, rate={rate}");
        }
    }
}
