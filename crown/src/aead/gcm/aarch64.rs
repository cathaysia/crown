#![allow(dead_code, unused_imports)]
//! ARMv8 AES+PMULL GCM stitch (`crypto/modes/asm/aes-gcm-armv8_64.pl`).
//!
//! The `aes_gcm_{enc,dec}_{128,192,256}_kernel` symbols fuse the AES-CTR
//! keystream with the GHASH over the produced ciphertext for whole blocks,
//! together with the `unroll8_eor3_*` variants for CPUs whose MIDR advertises
//! the fused AES+EOR3 pipeline (`IS_CPU_SUPPORT_UNROLL8_EOR3()`).
//!
//! They consume the AES *encryption* schedule (`aes_v8_set_encrypt_key`), a
//! `{Xi, H, Htable}` context whose relative layout is part of the ABI (the
//! kernels load Xi at Xip+0 and PMULL table entries at Xip+0x20, +0x40, +0x50
//! and +0x70, exactly as `struct gcm128_context` arranges `Yi, EKi, EK0, len,
//! Xi, H, Htable`), the counter block, and the length *in bits*. This module
//! mirrors `cipher_aes_gcm_hw_armv8.inc`, which is what puts the kernels live
//! in OpenSSL: `armv8_aes_gcm_encrypt` handles `len - len % 16` bytes and
//! leaves the tail to the caller.

#[cfg(crown_aarch64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/aead/gcm/aarch64.ts"),
    // The aarch64 operands carry `{v0.16b}`-style lane braces.
    options(raw)
);

#[cfg(crown_aarch64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/aead/gcm/aarch64_unroll8.ts"),
    // The aarch64 operands carry `{v0.16b}`-style lane braces.
    options(raw)
);

pub use crate::block::aes::key::AesKey;

/// `{ Xi, H, Htable[16]; }` — the relative order is part of the ABI: the
/// kernels load Xi from Xip+0 and the PMULL Htable from Xip+0x20 onwards.
/// `Htable` holds the `gcm_init_v8` output (H^1..H^8, 0xc0 bytes), which is
/// what `CRYPTO_gcm128_init` installs on PMULL-capable CPUs. `H` itself is
/// not read by the kernels but keeps the offsets aligned with
/// `struct gcm128_context`.
#[repr(C)]
pub struct GcmStitchCtx {
    pub xi: [u8; 16],
    pub h: [u8; 16],
    pub htable: [u8; 256],
}

extern "C" {
    fn aes_gcm_enc_128_kernel(
        inp: *const u8,
        bits: u64,
        out: *mut u8,
        xi: *mut u8,
        ivec: *mut u8,
        key: *const AesKey,
    );
    fn aes_gcm_dec_128_kernel(
        inp: *const u8,
        bits: u64,
        out: *mut u8,
        xi: *mut u8,
        ivec: *mut u8,
        key: *const AesKey,
    );
    fn aes_gcm_enc_192_kernel(
        inp: *const u8,
        bits: u64,
        out: *mut u8,
        xi: *mut u8,
        ivec: *mut u8,
        key: *const AesKey,
    );
    fn aes_gcm_dec_192_kernel(
        inp: *const u8,
        bits: u64,
        out: *mut u8,
        xi: *mut u8,
        ivec: *mut u8,
        key: *const AesKey,
    );
    fn aes_gcm_enc_256_kernel(
        inp: *const u8,
        bits: u64,
        out: *mut u8,
        xi: *mut u8,
        ivec: *mut u8,
        key: *const AesKey,
    );
    fn aes_gcm_dec_256_kernel(
        inp: *const u8,
        bits: u64,
        out: *mut u8,
        xi: *mut u8,
        ivec: *mut u8,
        key: *const AesKey,
    );

    fn unroll8_eor3_aes_gcm_enc_128_kernel(
        inp: *const u8,
        bits: u64,
        out: *mut u8,
        xi: *mut u8,
        ivec: *mut u8,
        key: *const AesKey,
    );
    fn unroll8_eor3_aes_gcm_dec_128_kernel(
        inp: *const u8,
        bits: u64,
        out: *mut u8,
        xi: *mut u8,
        ivec: *mut u8,
        key: *const AesKey,
    );
    fn unroll8_eor3_aes_gcm_enc_192_kernel(
        inp: *const u8,
        bits: u64,
        out: *mut u8,
        xi: *mut u8,
        ivec: *mut u8,
        key: *const AesKey,
    );
    fn unroll8_eor3_aes_gcm_dec_192_kernel(
        inp: *const u8,
        bits: u64,
        out: *mut u8,
        xi: *mut u8,
        ivec: *mut u8,
        key: *const AesKey,
    );
    fn unroll8_eor3_aes_gcm_enc_256_kernel(
        inp: *const u8,
        bits: u64,
        out: *mut u8,
        xi: *mut u8,
        ivec: *mut u8,
        key: *const AesKey,
    );
    fn unroll8_eor3_aes_gcm_dec_256_kernel(
        inp: *const u8,
        bits: u64,
        out: *mut u8,
        xi: *mut u8,
        ivec: *mut u8,
        key: *const AesKey,
    );
}

/// `AES_PMULL_CAPABLE`: the kernels are PMULL *and* AES instructions.
pub fn stitch_supported() -> bool {
    let cap = crate::utils::cpuid::armcap();
    cap & crate::utils::cpuid::ARMV8_PMULL != 0 && cap & crate::utils::cpuid::ARMV8_AES != 0
}

/// `IS_CPU_SUPPORT_UNROLL8_EOR3()`: the fused AES+EOR3 kernels are only
/// installed for CPUs whose MIDR advertises them (see crypto/armcap.c).
fn unroll8_supported() -> bool {
    crate::utils::cpuid::armcap() & crate::utils::cpuid::ARMV8_UNROLL8_EOR3 != 0
}

/// `AES_GCM_ENC_BYTES` / `AES_GCM_DEC_BYTES` of `crypto/aes_platform.h`: the
/// kernel is only engaged from this message size on.
pub const GCM_STITCH_MIN: usize = 512;

/// Initialise `{Xi, H, Htable}` from the GHASH subkey `H` (the AES encryption
/// of a zero block, in raw byte order). The caller must have checked
/// [`stitch_supported`].
pub fn init_ctx(h: &[u8; 16]) -> GcmStitchCtx {
    // CRYPTO_gcm128_init stores H byte-swapped per qword and gcm_init_v8
    // consumes it without a swap of its own.
    let mut h_swapped = [0u8; 16];
    for i in 0..8 {
        h_swapped[i] = h[7 - i];
        h_swapped[8 + i] = h[15 - i];
    }
    let mut htable = [0u8; 256];
    crate::block::aes::gcm::asm::init_v8_htable_into(&mut htable, &h_swapped);
    GcmStitchCtx {
        xi: [0u8; 16],
        h: *h,
        htable,
    }
}

/// Fuse AES-CTR + GHASH over `inp`, in place. `ivec` is the 16-byte counter
/// block (Yi) and is advanced past the processed blocks; `ctx.xi` accumulates
/// the GHASH of the ciphertext. Returns the number of bytes processed, always
/// a multiple of 16, mirroring `armv8_aes_gcm_encrypt`.
pub fn encrypt_inplace(
    key: &AesKey,
    inout: &mut [u8],
    ivec: &mut [u8; 16],
    ctx: &mut GcmStitchCtx,
) -> usize {
    let bytes = inout.len() & !15;
    if bytes == 0 {
        return 0;
    }
    let bits = (bytes as u64) * 8;
    unsafe {
        match (key.rounds, unroll8_supported()) {
            (10, false) => aes_gcm_enc_128_kernel(
                inout.as_ptr(),
                bits,
                inout.as_mut_ptr(),
                ctx.xi.as_mut_ptr(),
                ivec.as_mut_ptr(),
                key,
            ),
            (10, true) => unroll8_eor3_aes_gcm_enc_128_kernel(
                inout.as_ptr(),
                bits,
                inout.as_mut_ptr(),
                ctx.xi.as_mut_ptr(),
                ivec.as_mut_ptr(),
                key,
            ),
            (12, false) => aes_gcm_enc_192_kernel(
                inout.as_ptr(),
                bits,
                inout.as_mut_ptr(),
                ctx.xi.as_mut_ptr(),
                ivec.as_mut_ptr(),
                key,
            ),
            (12, true) => unroll8_eor3_aes_gcm_enc_192_kernel(
                inout.as_ptr(),
                bits,
                inout.as_mut_ptr(),
                ctx.xi.as_mut_ptr(),
                ivec.as_mut_ptr(),
                key,
            ),
            (14, false) => aes_gcm_enc_256_kernel(
                inout.as_ptr(),
                bits,
                inout.as_mut_ptr(),
                ctx.xi.as_mut_ptr(),
                ivec.as_mut_ptr(),
                key,
            ),
            (14, true) => unroll8_eor3_aes_gcm_enc_256_kernel(
                inout.as_ptr(),
                bits,
                inout.as_mut_ptr(),
                ctx.xi.as_mut_ptr(),
                ivec.as_mut_ptr(),
                key,
            ),
            _ => return 0,
        }
    }
    bytes
}

/// Fused AES-CTR + GHASH decrypt, same parameters as [`encrypt_inplace`].
/// The GHASH is accumulated over the ciphertext, which the kernel reads
/// before decrypting it in place.
pub fn decrypt_inplace(
    key: &AesKey,
    inout: &mut [u8],
    ivec: &mut [u8; 16],
    ctx: &mut GcmStitchCtx,
) -> usize {
    let bytes = inout.len() & !15;
    if bytes == 0 {
        return 0;
    }
    let bits = (bytes as u64) * 8;
    unsafe {
        match (key.rounds, unroll8_supported()) {
            (10, false) => aes_gcm_dec_128_kernel(
                inout.as_ptr(),
                bits,
                inout.as_mut_ptr(),
                ctx.xi.as_mut_ptr(),
                ivec.as_mut_ptr(),
                key,
            ),
            (10, true) => unroll8_eor3_aes_gcm_dec_128_kernel(
                inout.as_ptr(),
                bits,
                inout.as_mut_ptr(),
                ctx.xi.as_mut_ptr(),
                ivec.as_mut_ptr(),
                key,
            ),
            (12, false) => aes_gcm_dec_192_kernel(
                inout.as_ptr(),
                bits,
                inout.as_mut_ptr(),
                ctx.xi.as_mut_ptr(),
                ivec.as_mut_ptr(),
                key,
            ),
            (12, true) => unroll8_eor3_aes_gcm_dec_192_kernel(
                inout.as_ptr(),
                bits,
                inout.as_mut_ptr(),
                ctx.xi.as_mut_ptr(),
                ivec.as_mut_ptr(),
                key,
            ),
            (14, false) => aes_gcm_dec_256_kernel(
                inout.as_ptr(),
                bits,
                inout.as_mut_ptr(),
                ctx.xi.as_mut_ptr(),
                ivec.as_mut_ptr(),
                key,
            ),
            (14, true) => unroll8_eor3_aes_gcm_dec_256_kernel(
                inout.as_ptr(),
                bits,
                inout.as_mut_ptr(),
                ctx.xi.as_mut_ptr(),
                ivec.as_mut_ptr(),
                key,
            ),
            _ => return 0,
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stitch must reproduce the software AES-CTR keystream and the
    /// software GHASH over the produced ciphertext for every key size and
    /// every length class (below one 4-block group, exactly one, with a
    /// partial tail, and several groups).
    #[test]
    fn stitch_matches_software_ctr_and_ghash() {
        if !stitch_supported() {
            return;
        }
        use crate::block::aes::ghash::generic_ghash;
        use crate::block::aes::Aes;
        use crate::modes::ctr::Ctr;
        use crate::stream::StreamCipher;

        for key_len in [16usize, 24, 32] {
            let key_bytes = alloc::vec![0x11u8; key_len];
            let h = [0x22u8; 16];
            let cipher = Aes::new(&key_bytes).unwrap();
            let key = cipher.enc_schedule().0;

            let mut yi = [0u8; 16];
            yi[15] = 1;

            for len in [512usize, 528, 1024, 1552, 4096] {
                // Software keystream from the same counter block.
                let mut ks = alloc::vec![0u8; len & !15];
                cipher
                    .clone()
                    .to_ctr(&yi)
                    .unwrap()
                    .xor_key_stream(&mut ks)
                    .unwrap();

                let pt = alloc::vec![0x42u8; len];
                let mut ct = pt.clone();
                let mut ctr = yi;
                let mut ctx = init_ctx(&h);
                let n = encrypt_inplace(&key, &mut ct, &mut ctr, &mut ctx);
                assert_eq!(n, len & !15, "processed bytes key_len={key_len} len={len}");

                for i in 0..ks.len() {
                    assert_eq!(ct[i], pt[i] ^ ks[i], "keystream byte {i}");
                }

                let mut xi = [0u8; 16];
                generic_ghash(&mut xi, &h, &[&ct[..n]]);
                assert_eq!(ctx.xi, xi, "Xi after encrypt key_len={key_len} len={len}");

                // Decrypt must invert and land on the same GHASH state.
                let mut back = ct.clone();
                let mut ctr2 = yi;
                let mut ctx2 = init_ctx(&h);
                let n2 = decrypt_inplace(&key, &mut back, &mut ctr2, &mut ctx2);
                assert_eq!(n2, n);
                assert_eq!(&back[..n], &pt[..n], "decrypt key_len={key_len} len={len}");
                assert_eq!(ctr2, ctr, "counter after decrypt");
                assert_eq!(ctx2.xi, xi, "Xi after decrypt key_len={key_len} len={len}");
            }
        }
    }
}
