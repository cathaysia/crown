//! AES-NI + GHASH stitch for GCM (aesni-gcm-x86_64.pl).
//!
//! The stitch symbols and helpers are compiled and unit-tested; hooking them
//! into `seal`/`open` is still pending (see the module status in
//! `docs/algorithms-status.md`).
//!
//! `aesni_gcm_encrypt`/`aesni_gcm_decrypt` fuse AES-CTR and GHASH over the
//! bulk of the message. They consume OpenSSL `AES_KEY` round keys and a
//! `{Xi, H, Htbl[16]}` context whose relative layout is part of the ABI.
//! `Xi` is the running GHASH state over the consumed ciphertext, in the same
//! big-endian `u128` representation as `gcm128_context.Xi` — OpenSSL's
//! provider passes `ctx->gcm.Xi.u` and then keeps GHASHing the remainder, so
//! the accumulator has to line up exactly.


#![allow(dead_code, unused_imports)]
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/aead/gcm/x86_64.ts"),
    options(att_syntax)
);

/// OpenSSL `AES_KEY`: round keys in AES-NI native order (as produced by
/// `aesni_set_encrypt_key`) then the round count. The stitch consumes this
/// format, which differs from the C `AES_set_encrypt_key` layout in the
/// byte order of each round key word.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AesKey {
    pub rd_key: [u32; 60],
    pub rounds: u32,
}

/// `{ u128 Xi, H, Htable[16]; }` — the relative order is part of the ABI:
/// the stitch loads Xi from Xip+0, keeps H at Xip+0x10 and consumes the
/// clmul-format Htable (256 bytes) at Xip+0x20, matching
/// `struct gcm128_context`'s `Yi EKi EK0 len Xi H Htable` ordering.
#[repr(C)]
pub struct GcmStitchCtx {
    pub xi: [u8; 16],
    pub h: [u8; 16],
    pub htable: [[u8; 16]; 16],
}

/// Expand `user_key` into the AES-NI key schedule the stitch expects
/// (`aesni_set_encrypt_key` from aesni-x86_64.pl).
pub fn set_encrypt_key(user_key: &[u8], _bits: u32) -> AesKey {
    if crate::block::aes::aesni::supported() {
        let k = crate::block::aes::aesni::set_encrypt_key(user_key);
        AesKey {
            rd_key: k.rd_key,
            rounds: k.rounds,
        }
    } else {
        AesKey {
            rd_key: [0; 60],
            rounds: 0,
        }
    }
}

extern "C" {
    fn aesni_gcm_encrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        ivp: *mut u8,
        xip: *mut GcmStitchCtx,
    ) -> usize;
    fn aesni_gcm_decrypt(
        inp: *const u8,
        out: *mut u8,
        len: usize,
        key: *const AesKey,
        ivp: *mut u8,
        xip: *mut GcmStitchCtx,
    ) -> usize;
}

/// AES-NI requires CPUID leaf 1 ECX bit 25 (ia32cap[1] bit 25).
pub fn aesni_supported() -> bool {
    crate::utils::cpuid::ia32cap(1) & (1 << 25) != 0
}

/// The stitch body executes `vpclmulqdq`/`movbe`/VEX instructions, so it needs
/// PCLMULQDQ (bit 1), MOVBE (bit 22) and AVX (bit 28) plus OS YMM state —
/// exactly the `gcm_get_funcs` predicate that installs the AVX path (and
/// therefore the AVX Htable) in gcm128.c.
pub fn avx_supported() -> bool {
    const NEEDED: u32 = (1 << 1) | (1 << 22) | (1 << 28);
    let caps = crate::utils::cpuid::ia32cap(1);
    if caps & NEEDED != NEEDED || caps & (1 << 27) == 0 {
        return false; // PCLMULQDQ, MOVBE, AVX and OSXSAVE
    }
    // XCR0[2:1] == 3: XMM and YMM state enabled by the OS.
    (unsafe { core::arch::x86_64::_xgetbv(0) } & 0x6) == 0x6
}

/// Initialise `{Xi, H, Htable[16]}` from the GHASH hash subkey `H`. The table
/// must be the AVX one (`gcm_init_avx`, what `CRYPTO_gcm128_init` installs on
/// AVX+MOVBE CPUs): the stitch loads H^1..H^6 from offsets 0x00, 0x10, 0x30,
/// 0x40, 0x60, 0x70 and the Karatsuba salts from 0x20, 0x50, 0x80. The clmul
/// table is only 0x60 bytes and leaves H^5/H^6 zero, which corrupts `ctx.xi`.
///
/// The caller must have checked [`aesni_supported`] and [`avx_supported`]:
/// `gcm_init_avx` is VEX-encoded, like the stitch itself.
pub fn init_ctx(h: &[u8; 16]) -> GcmStitchCtx {
    GcmStitchCtx {
        xi: [0u8; 16],
        h: *h,
        htable: {
            let mut table = [[0u8; 16]; 16];
            let flat = crate::block::aes::gcm::asm::init_avx_htable(h);
            for (i, block) in table.iter_mut().enumerate() {
                *block = flat[i * 16..(i + 1) * 16].try_into().unwrap();
            }
            table
        },
    }
}

/// Fuse AES-CTR + GHASH over `inp`. `ivp` is the 16-byte counter block (Yi);
/// `ctx.xi` is the running GHASH accumulator. Returns bytes processed.
pub fn encrypt(
    key: &AesKey,
    inp: &[u8],
    out: &mut [u8],
    ivp: &mut [u8],
    ctx: &mut GcmStitchCtx,
) -> usize {
    unsafe {
        aesni_gcm_encrypt(
            inp.as_ptr(),
            out.as_mut_ptr(),
            inp.len(),
            key,
            ivp.as_mut_ptr(),
            ctx,
        )
    }
}

/// Fused AES-CTR + GHASH decrypt. Same parameters as [`encrypt`].
pub fn decrypt(
    key: &AesKey,
    inp: &[u8],
    out: &mut [u8],
    ivp: &mut [u8],
    ctx: &mut GcmStitchCtx,
) -> usize {
    unsafe {
        aesni_gcm_decrypt(
            inp.as_ptr(),
            out.as_mut_ptr(),
            inp.len(),
            key,
            ivp.as_mut_ptr(),
            ctx,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS-197 Appendix A.1: the AES-NI schedule must encrypt the reference
    // block to the reference ciphertext (the schedule bytes themselves are
    // in AES-NI native word order, not the C big-endian word order).
    #[test]
    fn aes128_schedule_matches_fips197() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let k = set_encrypt_key(&key, 128);
        // aesni_set_encrypt_key stores rounds-1 (the AES-NI asm convention).
        assert_eq!(k.rounds, 9);

        let mut block = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        crate::block::aes::aesni::encrypt_block(&mut block, &{
            crate::block::aes::aesni::set_encrypt_key(&key)
        });
        assert_eq!(
            block,
            [
                0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
                0x0b, 0x32,
            ]
        );
    }

    // The stitch must match the software AES-CTR keystream and the software
    // GHASH over the produced ciphertext (a self-consistent round trip alone
    // would not catch a wrong key schedule or Htable).
    #[test]
    fn stitch_matches_software_ctr_and_ghash() {
        if !(aesni_supported() && avx_supported()) {
            return;
        }
        use crate::block::aes::Aes;
        use crate::modes::ctr::Ctr;
        use crate::stream::StreamCipher;

        let key_bytes = [0x11u8; 16];
        let h = [0x22u8; 16];
        let key = set_encrypt_key(&key_bytes, 128);

        // Software AES-CTR with the counter block starting at Yi.
        let cipher = Aes::new(&key_bytes).unwrap();
        let mut yi = [0u8; 16];
        yi[15] = 1;
        let mut ks = [0u8; 384];
        cipher
            .clone()
            .to_ctr(&yi)
            .unwrap()
            .xor_key_stream(&mut ks)
            .unwrap();

        let pt = [0x42u8; 384];
        let mut ct = [0u8; 384];
        let mut ctr = yi;
        let mut ctx = init_ctx(&h);
        let n = encrypt(&key, &pt, &mut ct, &mut ctr, &mut ctx);
        assert_eq!(n, 384);

        for i in 0..384 {
            assert_eq!(ct[i], pt[i] ^ ks[i], "keystream byte {i}");
        }

        // The stitch GHASHes the bytes it consumes, so `ctx.xi` must equal the
        // software GHASH over the ciphertext — OpenSSL's provider hands the
        // stitch `ctx->gcm.Xi.u` and then keeps accumulating from it, so a
        // stale or differently-represented Htable (e.g. the clmul one, which
        // leaves H^5/H^6 zero) shows up here.
        let mut xi = [0u8; 16];
        crate::block::aes::gcm::ghash::generic_ghash(&mut xi, &h, &[&ct]);
        assert_eq!(ctx.xi, xi, "Xi after encrypt");

        // Golden values from the perl-generated reference asm
        // (aesni-gcm-x86_64.pl + gcm_init_avx) driven with these same inputs,
        // which pins the port itself rather than only its self-consistency.
        assert_eq!(
            &ct[..16],
            [
                0xd1, 0x80, 0x13, 0x5b, 0xd5, 0x1d, 0x1c, 0xbe, 0xeb, 0xb6, 0xb9, 0x4a, 0x04, 0x6c,
                0x3c, 0x87,
            ]
        );
        assert_eq!(
            ctx.xi,
            [
                0xac, 0xb2, 0x8e, 0x2b, 0x33, 0x81, 0x2b, 0xef, 0x21, 0x5e, 0x2f, 0x69, 0x3d, 0x58,
                0x1f, 0x23,
            ]
        );

        // Decrypt must invert, update the counter block identically and leave
        // the same GHASH state (it absorbs the same ciphertext).
        let mut back = [0u8; 384];
        let mut ctr2 = yi;
        let mut ctx2 = init_ctx(&h);
        let n = decrypt(&key, &ct, &mut back, &mut ctr2, &mut ctx2);
        assert_eq!(n, 384);
        assert_eq!(back, pt);
        assert_eq!(ctr2, ctr);
        assert_eq!(ctx2.xi, xi, "Xi after decrypt");
    }

    #[test]
    fn stitch_round_trip() {
        if !(aesni_supported() && avx_supported()) {
            return;
        }
        let key = set_encrypt_key(&[0x11; 16], 128);
        let mut ctx = init_ctx(&[0x22; 16]);
        let mut yi = [0u8; 16];
        yi[15] = 1; // counter = 1
                    // Encrypt needs >= 288 bytes (0x60*3); decrypt >= 96.
        let pt = [0x42u8; 384];
        let mut ct = [0u8; 384];
        let n = encrypt(&key, &pt, &mut ct, &mut yi, &mut ctx);
        assert_eq!(n, 384);
        assert_ne!(ct, pt);

        let mut ctx2 = init_ctx(&[0x22; 16]);
        let mut yi2 = [0u8; 16];
        yi2[15] = 1;
        let mut back = [0u8; 384];
        let n = decrypt(&key, &ct, &mut back, &mut yi2, &mut ctx2);
        assert_eq!(n, 384);
        assert_eq!(back, pt);
    }
}

/// In-place fused encrypt (same buffer for input and output).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn encrypt_inplace(
    key: &AesKey,
    inout: &mut [u8],
    ivp: &mut [u8],
    ctx: &mut GcmStitchCtx,
) -> usize {
    unsafe {
        aesni_gcm_encrypt(
            inout.as_ptr(),
            inout.as_mut_ptr(),
            inout.len(),
            key,
            ivp.as_mut_ptr(),
            ctx,
        )
    }
}

/// In-place fused decrypt (same buffer for input and output).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn decrypt_inplace(
    key: &AesKey,
    inout: &mut [u8],
    ivp: &mut [u8],
    ctx: &mut GcmStitchCtx,
) -> usize {
    unsafe {
        aesni_gcm_decrypt(
            inout.as_ptr(),
            inout.as_mut_ptr(),
            inout.len(),
            key,
            ivp.as_mut_ptr(),
            ctx,
        )
    }
}
