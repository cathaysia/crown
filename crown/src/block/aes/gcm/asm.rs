//! GHASH assembly implementation using PCLMULQDQ.

use super::GCM_BLOCK_SIZE;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/block/aes/gcm/x86_64.ts"),
    options(att_syntax)
);

extern "C" {
    fn gcm_init_clmul(htbl: *mut u8, h: *const u8);
    fn gcm_init_avx(htbl: *mut u8, h: *const u8);
    fn gcm_ghash_clmul(xi: *mut u8, htbl: *const u8, inp: *const u8, len: usize);
}

/// Build the 256-byte AVX-format Htable (H^1..H^8 at 0x00..0x70, Karatsuba
/// salts at 0x20/0x50/0x80, 0xc0 bytes written) exactly as CRYPTO_gcm128_init
/// does when gcm_get_funcs picks the AVX path: H is byte-swapped per qword
/// before the assembly sees it. The aesni-gcm stitch reads its six H keys and
/// three salts from this layout, so the shorter clmul table (which only holds
/// H^1..H^4 and zeroes the rest) must not be handed to it.
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

/// GHASH via gcm_init_clmul/gcm_ghash_clmul. Only complete blocks are passed
/// to the assembly, mirroring OpenSSL's gcm128.c which zero-pads partial
/// blocks in C.
#[allow(dead_code)] // kept for parity with ghash_absorb
pub(crate) fn ghash(out: &mut [u8; GCM_BLOCK_SIZE], h: &[u8; GCM_BLOCK_SIZE], inputs: &[&[u8]]) {
    let mut state = [0u8; GCM_BLOCK_SIZE];
    ghash_absorb(&mut state, h, inputs);
    *out = state;
}

/// GHASH continuing from `state`. `gcm_ghash_clmul` accumulates into `xi`.
pub(crate) fn ghash_absorb(
    state: &mut [u8; GCM_BLOCK_SIZE],
    h: &[u8; GCM_BLOCK_SIZE],
    inputs: &[&[u8]],
) {
    // gcm_init_clmul stores H^1..H^4 plus two Karatsuba salts (0x60 bytes).
    let mut htable = [0u8; 96];
    // Mirror CRYPTO_gcm128_init: H is byte-swapped per qword before the
    // assembly sees it.
    let mut h_swapped = [0u8; GCM_BLOCK_SIZE];
    for i in 0..8 {
        h_swapped[i] = h[7 - i];
        h_swapped[8 + i] = h[15 - i];
    }
    unsafe { gcm_init_clmul(htable.as_mut_ptr(), h_swapped.as_ptr()) };

    let mut xi = *state;
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
