#![allow(dead_code, unused_imports)]
//! GHASH assembly implementation (PCLMULQDQ on x86_64, PMULL on aarch64).

use super::GCM_BLOCK_SIZE;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
use alloc::vec::Vec;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/gcm/x86_64.ts"),
    options(att_syntax)
);

#[cfg(crown_aarch64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/gcm/aarch64.ts"),
    // The aarch64 operands carry `{v0.16b}`-style lane braces.
    options(raw)
);

extern "C" {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    fn gcm_init_clmul(htbl: *mut u8, h: *const u8);
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    fn gcm_init_avx(htbl: *mut u8, h: *const u8);
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    fn gcm_ghash_clmul(xi: *mut u8, htbl: *const u8, inp: *const u8, len: usize);
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    fn gcm_ghash_avx(xi: *mut u8, htbl: *const u8, inp: *const u8, len: usize);

    /// Builds the 256-byte PMULL Htable (H^1..H^8) from H in the byte-swapped
    /// form CRYPTO_gcm128_init stores in `ctx->H.u`.
    #[cfg(crown_aarch64_asm)]
    fn gcm_init_v8(htbl: *mut u8, h: *const u8);
    #[cfg(crown_aarch64_asm)]
    fn gcm_ghash_v8(xi: *mut u8, htbl: *const u8, inp: *const u8, len: usize);
}

/// PMULL (ARMv8 crypto extensions) backs the aarch64 GHASH bodies.
#[cfg(crown_aarch64_asm)]
pub(crate) fn ghash_pmull_supported() -> bool {
    crate::utils::cpuid::armcap() & crate::utils::cpuid::ARMV8_PMULL != 0
}

/// AVX+PCLMULQDQ+OSXSAVE+YMM state — what gcm128.c's gcm_get_funcs needs
/// before installing the AVX Htable / gcm_ghash_avx path.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) fn ghash_avx_supported() -> bool {
    use crate::utils::cpuid::ia32cap;
    const NEEDED: u32 = (1 << 1) | (1 << 28); // PCLMULQDQ + AVX
    let caps = ia32cap(1);
    if caps & NEEDED != NEEDED || caps & (1 << 27) == 0 {
        return false;
    }
    (unsafe { core::arch::x86_64::_xgetbv(0) } & 0x6) == 0x6
}

/// Build the 256-byte AVX-format Htable (H^1..H^8 at 0x00..0x70, Karatsuba
/// salts at 0x20/0x50/0x80, 0xc0 bytes written) exactly as CRYPTO_gcm128_init
/// does when gcm_get_funcs picks the AVX path: H is byte-swapped per qword
/// before the assembly sees it. The aesni-gcm stitch reads its six H keys and
/// three salts from this layout, so the shorter clmul table (which only holds
/// H^1..H^4 and zeroes the rest) must not be handed to it.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) fn init_avx_htable(h: &[u8; GCM_BLOCK_SIZE]) -> [u8; 256] {
    let mut htable = [0u8; 256];
    let mut h_swapped = [0u8; GCM_BLOCK_SIZE];
    for i in 0..8 {
        h_swapped[i] = h[7 - i];
        h_swapped[8 + i] = h[15 - i];
    }
    unsafe { gcm_init_avx(htable.as_mut_ptr(), h_swapped.as_ptr()) };
    htable
}

/// Build the 256-byte PMULL Htable (H^1..H^8, 0xc0 bytes written) into
/// `htable`, mirroring the `ginit` call of `CRYPTO_gcm128_init`. `h_swapped`
/// is H byte-swapped per qword — the form `ctx->H.u` holds, and the form
/// `gcm_init_v8` consumes.
#[cfg(crown_aarch64_asm)]
pub(crate) fn init_v8_htable_into(htable: &mut [u8; 256], h_swapped: &[u8; GCM_BLOCK_SIZE]) {
    unsafe { gcm_init_v8(htable.as_mut_ptr(), h_swapped.as_ptr()) };
}

/// GHASH over the assembly bodies. Only complete blocks are passed to the
/// assembly, mirroring OpenSSL's gcm128.c which zero-pads partial blocks in
/// C.
#[allow(dead_code)] // kept for parity with ghash_absorb
pub(crate) fn ghash(out: &mut [u8; GCM_BLOCK_SIZE], h: &[u8; GCM_BLOCK_SIZE], inputs: &[&[u8]]) {
    let mut state = [0u8; GCM_BLOCK_SIZE];
    ghash_absorb(&mut state, h, inputs);
    *out = state;
}

/// GHASH continuing from `state`. Accumulates into `xi`; prefers the AVX
/// 8x body (gcm_ghash_avx over the AVX Htable) when the CPU allows it, and
/// the PMULL body (gcm_ghash_v8) on aarch64.
pub(crate) fn ghash_absorb(
    state: &mut [u8; GCM_BLOCK_SIZE],
    h: &[u8; GCM_BLOCK_SIZE],
    inputs: &[&[u8]],
) {
    #[cfg(crown_aarch64_asm)]
    {
        // CRYPTO_gcm128_init stores H byte-swapped per qword (`ctx->H.u`) and
        // gcm_init_v8 consumes it without a swap of its own; Xi on the other
        // hand is read and written in raw byte order.
        let mut h_swapped = [0u8; GCM_BLOCK_SIZE];
        for i in 0..8 {
            h_swapped[i] = h[7 - i];
            h_swapped[8 + i] = h[15 - i];
        }
        let mut htable = [0u8; 256];
        unsafe { gcm_init_v8(htable.as_mut_ptr(), h_swapped.as_ptr()) };

        let mut xi = *state;
        for input in inputs {
            let full = input.len() & !15;
            if full >= 16 {
                unsafe {
                    gcm_ghash_v8(xi.as_mut_ptr(), htable.as_ptr(), input.as_ptr(), full);
                }
            }

            let tail = &input[full..];
            if !tail.is_empty() {
                let mut block = [0u8; GCM_BLOCK_SIZE];
                block[..tail.len()].copy_from_slice(tail);
                unsafe {
                    gcm_ghash_v8(xi.as_mut_ptr(), htable.as_ptr(), block.as_ptr(), 16);
                }
            }
        }

        *state = xi;
    }

    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        // Mirror CRYPTO_gcm128_init: H is byte-swapped per qword before the
        // x86_64 assembly sees it.
        let mut h_swapped = [0u8; GCM_BLOCK_SIZE];
        for i in 0..8 {
            h_swapped[i] = h[7 - i];
            h_swapped[8 + i] = h[15 - i];
        }

        let mut xi = *state;

        if ghash_avx_supported() {
            // gcm_init_avx writes the 256-byte AVX table (H^1..H^8 + salts).
            let htable = init_avx_htable(h);
            for input in inputs {
                let full = input.len() & !15;
                if full >= 16 {
                    unsafe {
                        gcm_ghash_avx(xi.as_mut_ptr(), htable.as_ptr(), input.as_ptr(), full);
                    }
                }
                let tail = &input[full..];
                if !tail.is_empty() {
                    let mut block = [0u8; GCM_BLOCK_SIZE];
                    block[..tail.len()].copy_from_slice(tail);
                    unsafe {
                        gcm_ghash_avx(xi.as_mut_ptr(), htable.as_ptr(), block.as_ptr(), 16);
                    }
                }
            }
            *state = xi;
            return;
        }

        // gcm_init_clmul stores H^1..H^4 plus two Karatsuba salts (0x60 bytes).
        let mut htable = [0u8; 96];
        unsafe { gcm_init_clmul(htable.as_mut_ptr(), h_swapped.as_ptr()) };
        for input in inputs {
            let full = input.len() & !15;
            if full >= 16 {
                unsafe {
                    gcm_ghash_clmul(xi.as_mut_ptr(), htable.as_ptr(), input.as_ptr(), full);
                }
            }

            let tail = &input[full..];
            if !tail.is_empty() {
                let mut block = [0u8; GCM_BLOCK_SIZE];
                block[..tail.len()].copy_from_slice(tail);
                unsafe {
                    gcm_ghash_clmul(xi.as_mut_ptr(), htable.as_ptr(), block.as_ptr(), 16);
                }
            }
        }

        *state = xi;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::aes::ghash::generic_ghash;

    /// The hardware GHASH (gcm_ghash_avx on x86_64, gcm_ghash_v8 on aarch64)
    /// must match the portable GHASH for every length class the bodies
    /// special-case: <16, 16..128 short path, 128..256 tail-after-prologue,
    /// and full multi-block loop iterations.
    #[test]
    fn ghash_avx_matches_generic() {
        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        if !ghash_avx_supported() {
            return;
        }
        #[cfg(crown_aarch64_asm)]
        if !ghash_pmull_supported() {
            return;
        }
        let h = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        // known GHASH test vector (NIST GCM spec, H above / empty data)
        let mut expect = [0u8; 16];
        generic_ghash(&mut expect, &h, &[]);

        let mut got = [0u8; 16];
        ghash_absorb(&mut got, &h, &[]);
        assert_eq!(got, expect, "empty");

        for &len in &[
            1usize, 15, 16, 17, 31, 32, 48, 64, 80, 96, 112, 127, 128, 129, 144, 160, 192, 200,
            255, 256, 257, 300, 384, 512, 1024,
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i * 17 + 3) as u8).collect();
            let mut expect = [0u8; 16];
            generic_ghash(&mut expect, &h, &[&data]);

            let mut got = [0u8; 16];
            ghash_absorb(&mut got, &h, &[&data]);
            assert_eq!(got, expect, "single slice len={len}");

            // multi-slice absorb must match generic with the same slices
            // (each slice is zero-padded independently, so this is *not*
            // the same as a one-shot over the concatenation).
            if len > 1 {
                let (a, b) = data.split_at(len / 2);
                let mut expect2 = [0u8; 16];
                generic_ghash(&mut expect2, &h, &[a, b]);
                let mut got2 = [0u8; 16];
                ghash_absorb(&mut got2, &h, &[a, b]);
                assert_eq!(got2, expect2, "split len={len}");
            }
        }

        // chained absorb (AAD -> data) equals one-shot over the concatenation
        let aad = b"header-aad";
        let msg: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let mut chained = [0u8; 16];
        ghash_absorb(&mut chained, &h, &[aad]);
        ghash_absorb(&mut chained, &h, &[&msg]);
        let mut expect = [0u8; 16];
        generic_ghash(&mut expect, &h, &[aad, &msg]);
        assert_eq!(chained, expect, "chained absorb");
    }
}
