#![allow(dead_code, unused_imports)]
//! riscv64 AES-GCM stitch (`crypto/modes/asm/aes-gcm-riscv64-zvkb-zvkg-zvkned.pl`).
//!
//! `rv64i_zvkb_zvkg_zvkned_aes_gcm_{encrypt,decrypt}` fuse the AES-CTR
//! keystream with the GHASH over the produced ciphertext for whole blocks,
//! using the Zvkg `vgmul`/`vghsh` operations for the field arithmetic. They
//! are one entry point per direction for all key sizes (the body branches on
//! `key->rounds`), unlike the aarch64 kernels' per-key-size symbols.
//!
//! The context they read is the tail of `GCM128_CONTEXT`: the calls pass
//! `&Xi` and the helpers address `Htable[0]` as `Xi+32` ("The H is at
//! `gcm128_context.Htable[0]`(addr(Xi)+16*2)"), so `Xi`, `H` and the Htable
//! must stay contiguous in that order, exactly like `struct gcm128_context`
//! arranges `Yi, EKi, EK0, len, Xi, H, Htable`. `Htable[0]` holds H itself
//! (in the raw GHASH representation), which the kernel raises to the needed
//! power internally, so [`init_ctx`] only has to install the Zvkg table.
//!
//! Following `e_aes.c`, the kernel handles `len - len % 16` bytes and leaves
//! the tail to the caller, writes the counter block for the *next* block back
//! to `ivec`, and updates `Xi` in place; it is engaged from 32 (encrypt) /
//! 16 (decrypt) bytes on, which is the `AES_GCM_ASM(gctx)` guard there. The
//! caller must only reach it when the cipher is the Zvkned one with the Zvkb
//! CTR32 routine installed *and* the GHASH is the Zvkg one, which is what
//! `AES_GCM_ASM` checks via the function pointers -- [`stitch_supported`] is
//! that conjunction.

#[cfg(crown_riscv64_asm)]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/aead/gcm/riscv64.ts"),
    options(raw)
);

pub use crate::block::aes::key::AesKey;

/// `{ Xi, H, Htable[16]; }` — the relative order is part of the ABI: the
/// kernel loads Xi from `Xip+0` and H from `Xip+32`. `H` is the raw GHASH
/// subkey, which the kernel does not read (it takes H from the table) but
/// which keeps the offsets aligned with `struct gcm128_context`.
#[repr(C, align(16))]
pub struct GcmStitchCtx {
    pub xi: [u8; 16],
    pub h: [u8; 16],
    pub htable: [u8; 256],
}

extern "C" {
    fn rv64i_zvkb_zvkg_zvkned_aes_gcm_encrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        ivec: *mut u8,
        xi: *mut u8,
    ) -> usize;
    fn rv64i_zvkb_zvkg_zvkned_aes_gcm_decrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        ivec: *mut u8,
        xi: *mut u8,
    ) -> usize;
}

/// `AES_GCM_ASM(gctx)` for the Zvkg tier: the cipher must be the Zvkned one
/// with `rv64i_zvkb_zvkned_ctr32_encrypt_blocks` installed (Zvkb present) and
/// the GHASH must be `gcm_ghash_rv64i_zvkg`.
#[cfg(crown_riscv64_asm)]
pub fn stitch_supported() -> bool {
    use crate::block::aes::gcm::asm::{riscv_ghash_tier, RiscvGhashTier};
    use crate::block::aes::riscv64::{tier, Tier};
    tier() == Tier::Zvkned
        && crate::utils::cpuid::has_zvkb()
        && matches!(riscv_ghash_tier(), Some(RiscvGhashTier::Zvkg { .. }))
}

/// `AES_GCM_ENC_BYTES` / `AES_GCM_DEC_BYTES` of `crypto/aes_platform.h`; the
/// `AES_GCM_ASM` guards of `e_aes.c` use `len >= 32` and `len >= 16`.
pub const GCM_STITCH_MIN_ENC: usize = 32;
pub const GCM_STITCH_MIN_DEC: usize = 16;

/// Initialise `{Xi, H, Htable}` from the GHASH subkey `H` (the AES encryption
/// of a zero block, in raw byte order). The caller must have checked
/// [`stitch_supported`].
#[cfg(crown_riscv64_asm)]
pub fn init_ctx(h: &[u8; 16]) -> GcmStitchCtx {
    // CRYPTO_gcm128_init stores H byte-swapped per qword and the riscv64 init
    // routines consume it without a swap of their own.
    let mut h_swapped = [0u8; 16];
    for i in 0..8 {
        h_swapped[i] = h[7 - i];
        h_swapped[8 + i] = h[15 - i];
    }
    let mut htable = [0u8; 256];
    crate::block::aes::gcm::asm::init_zvkg_htable_into(&mut htable, &h_swapped);
    GcmStitchCtx {
        xi: [0u8; 16],
        h: *h,
        htable,
    }
}

/// Fuse AES-CTR + GHASH over `inp`, in place. `ivec` is the big-endian
/// counter block (Yi), already advanced to the first data block (J0+1); it is
/// advanced past the processed blocks. `ctx.xi` accumulates the GHASH of the
/// ciphertext, in the same representation the portable GHASH uses. Returns
/// the number of bytes processed, always a multiple of 16.
#[cfg(crown_riscv64_asm)]
pub fn encrypt_inplace(
    key: &AesKey,
    inout: &mut [u8],
    ivec: &mut [u8; 16],
    ctx: &mut GcmStitchCtx,
) -> usize {
    unsafe {
        rv64i_zvkb_zvkg_zvkned_aes_gcm_encrypt(
            inout.as_ptr(),
            inout.as_mut_ptr(),
            inout.len(),
            key,
            ivec.as_mut_ptr(),
            ctx.xi.as_mut_ptr(),
        )
    }
}

/// Fused AES-CTR + GHASH decrypt, same parameters as [`encrypt_inplace`]. The
/// GHASH is accumulated over the ciphertext, which the kernel reads before
/// decrypting it in place.
#[cfg(crown_riscv64_asm)]
pub fn decrypt_inplace(
    key: &AesKey,
    inout: &mut [u8],
    ivec: &mut [u8; 16],
    ctx: &mut GcmStitchCtx,
) -> usize {
    unsafe {
        rv64i_zvkb_zvkg_zvkned_aes_gcm_decrypt(
            inout.as_ptr(),
            inout.as_mut_ptr(),
            inout.len(),
            key,
            ivec.as_mut_ptr(),
            ctx.xi.as_mut_ptr(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stitch must reproduce the software AES-CTR keystream and the
    /// software GHASH over the produced ciphertext for every key size and
    /// every length class (below one vector group, exactly one, several
    /// groups, with and without a partial tail).
    #[test]
    fn stitch_matches_software_ctr_and_ghash() {
        if !stitch_supported() {
            return;
        }
        use crate::block::aes::ghash::generic_ghash;
        use crate::block::aes::Aes;
        // `to_ctr` is the trait method the keystream comes from.
        use crate::modes::ctr::Ctr;
        use crate::stream::StreamCipher;

        for key_len in [16usize, 24, 32] {
            let key_bytes = alloc::vec![0x11u8; key_len];
            let h = [0x22u8; 16];
            let cipher = Aes::new(&key_bytes).unwrap();
            let key = cipher.enc_schedule().0;

            let mut yi = [0u8; 16];
            yi[15] = 1;

            for len in [16usize, 17, 32, 48, 64, 80, 128, 256, 1024, 4096, 4113] {
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
                    assert_eq!(ct[i], pt[i] ^ ks[i], "keystream byte {i} len={len}");
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
                assert_eq!(ctr2, ctr, "counter after decrypt len={len}");
                assert_eq!(ctx2.xi, xi, "Xi after decrypt key_len={key_len} len={len}");
            }
        }
    }

    /// End to end: the stitched seal/open of a long message must agree with
    /// the portable driver, ciphertext and tag alike.
    #[test]
    fn seal_open_match_generic() {
        if !stitch_supported() {
            return;
        }
        use crate::aead::Aead;
        use crate::block::aes::gcm::generic::{open_generic, seal_generic};
        use crate::block::aes::gcm::Gcm;
        use crate::block::aes::Aes;

        for key_len in [16usize, 24, 32] {
            let key = alloc::vec![0x5au8; key_len];
            let nonce = [0x11u8; 12];
            let aad = b"aad-for-the-riscv64-stitch";

            for len in [0usize, 31, 32, 33, 1024, 4096, 4097] {
                let pt: alloc::vec::Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
                let cipher = Aes::new(&key).unwrap();
                let g = Gcm::<12, 16>::new(cipher).unwrap();
                // The public constructors return `impl Aead`; the portable
                // driver needs the concrete `Gcm` for `seal_generic`.

                let mut stitched = pt.clone();
                let tag = g
                    .seal_in_place_separate_tag(&mut stitched, &nonce, aad)
                    .unwrap();

                let mut portable = pt.clone();
                let tag_portable = seal_generic::<12, 16>(&mut portable, &g, &nonce, aad);

                assert_eq!(stitched, portable, "ciphertext key_len={key_len} len={len}");
                assert_eq!(tag, tag_portable, "tag key_len={key_len} len={len}");

                // The stitched decrypt must accept the stitched tag.
                let mut round = stitched.clone();
                g.open_in_place_separate_tag(&mut round, &tag, &nonce, aad)
                    .unwrap_or_else(|e| panic!("open failed key_len={key_len} len={len}: {e:?}"));
                assert_eq!(round, pt, "roundtrip key_len={key_len} len={len}");

                // ... and so must the portable one.
                let mut round = stitched.clone();
                open_generic::<12, 16>(&mut round, &g, &nonce, aad, &tag)
                    .unwrap_or_else(|e| panic!("generic open failed len={len}: {e:?}"));
                assert_eq!(round, pt);
            }
        }
    }
}
