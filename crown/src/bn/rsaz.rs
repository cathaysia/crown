#![allow(dead_code, unused_mut, unused_imports)]
//! RSAZ assembly helpers (rsaz-x86_64.pl / rsaz-avx2.pl) for x86_64.
//!
//! OpenSSL's `crypto/bn/asm/rsaz-x86_64.pl` provides 512-bit Montgomery
//! primitives (R = 2^512, 8 limbs) used by `RSAZ_512_mod_exp`, and
//! `crypto/bn/asm/rsaz-avx2.pl` provides the 1024-bit AVX2 family used by
//! `RSAZ_1024_mod_exp_avx2`. Both are translated, exported and unit-tested
//! here; they are not yet dispatched from [`crate::bn::Montgomery`]
//! (the mont5 `bn_mul_mont`/`bn_power5` stack still owns `pow_consttime`).
//!
//! C ABI (`$win64=0`, unix SysV):
//!
//! ```text
//! void rsaz_512_mul(BN_ULONG out[8], const BN_ULONG a[8], const BN_ULONG b[8],
//!                   const BN_ULONG n[8], BN_ULONG n0);
//! void rsaz_512_sqr(BN_ULONG out[8], const BN_ULONG a[8], const BN_ULONG n[8],
//!                   BN_ULONG n0, int times);
//! void rsaz_512_mul_by_one(BN_ULONG out[8], const BN_ULONG a[8],
//!                          const BN_ULONG n[8], BN_ULONG n0);
//! void rsaz_512_mul_gather4(BN_ULONG out[8], const BN_ULONG a[8],
//!                           const BN_ULONG tbl[], const BN_ULONG n[8],
//!                           BN_ULONG n0, unsigned power);
//! void rsaz_512_mul_scatter4(BN_ULONG out[8], const BN_ULONG a[8],
//!                            const BN_ULONG n[8], BN_ULONG n0,
//!                            BN_ULONG tbl[], unsigned power);
//! void rsaz_512_scatter4(BN_ULONG tbl[], const BN_ULONG val[8], int power);
//! void rsaz_512_gather4(BN_ULONG val[8], const BN_ULONG tbl[], int power);
//!
//! void rsaz_1024_sqr_avx2(void *rp, const void *ap, const void *np,
//!                         BN_ULONG n0, int rep);
//! void rsaz_1024_mul_avx2(void *rp, const void *ap, const void *bp,
//!                         const void *np, BN_ULONG n0);
//! void rsaz_1024_norm2red_avx2(void *red, const void *norm);
//! void rsaz_1024_red2norm_avx2(void *norm, const void *red);
//! void rsaz_1024_scatter5_avx2(void *tbl, const void *val, int i);
//! void rsaz_1024_gather5_avx2(void *val, const void *tbl, int i);
//! int  rsaz_avx2_eligible(void);
//! ```
//!
//! `n0` is always `-n^-1 mod 2^64`. The 1024-bit family operates on the
//! 29-bit-digit redundant form (36 digits laid out as 40 u64 words, 320
//! bytes); `norm2red`/`red2norm` convert to and from the ordinary 16-limb
//! little-endian form. Montgomery R for the AVX2 AMM is 2^1044 = 2^(29*36).
//!
//! See `rsaz/NOTES.md` for config pins and re-verification.

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/bn/rsaz_x86_64.ts"),
    options(att_syntax)
);

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/bn/rsaz_avx2_x86_64.ts"),
    options(att_syntax)
);

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
extern "C" {
    fn rsaz_512_sqr(out: *mut u64, inp: *const u64, n: *const u64, n0: u64, times: i32);
    fn rsaz_512_mul(out: *mut u64, a: *const u64, b: *const u64, n: *const u64, n0: u64);
    fn rsaz_512_mul_gather4(
        out: *mut u64,
        a: *const u64,
        tbl: *const u64,
        n: *const u64,
        n0: u64,
        power: u32,
    );
    fn rsaz_512_mul_scatter4(
        out: *mut u64,
        a: *const u64,
        n: *const u64,
        n0: u64,
        tbl: *mut u64,
        power: u32,
    );
    fn rsaz_512_mul_by_one(out: *mut u64, a: *const u64, n: *const u64, n0: u64);
    fn rsaz_512_scatter4(tbl: *mut u64, val: *const u64, power: i32);
    fn rsaz_512_gather4(val: *mut u64, tbl: *const u64, power: i32);

    fn rsaz_1024_sqr_avx2(rp: *mut u64, ap: *const u64, np: *const u64, n0: u64, rep: i32);
    fn rsaz_1024_mul_avx2(rp: *mut u64, ap: *const u64, bp: *const u64, np: *const u64, n0: u64);
    fn rsaz_1024_norm2red_avx2(red: *mut u64, norm: *const u64);
    fn rsaz_1024_red2norm_avx2(norm: *mut u64, red: *const u64);
    fn rsaz_1024_scatter5_avx2(tbl: *mut u64, val: *const u64, i: i32);
    fn rsaz_1024_gather5_avx2(val: *mut u64, tbl: *const u64, i: i32);
    fn rsaz_avx2_eligible() -> i32;
}

/// Word count of the 512-bit helpers' operands (R = 2^512).
pub const LIMBS_512: usize = 8;

/// Word count of a 1024-bit number in normal form (R = 2^1024 for the C
/// callers; the AMM's internal R is 2^1044).
pub const LIMBS_1024: usize = 16;

/// Word count of the AVX2 29-bit-digit redundant form (36 digits + 4 zero
/// pad words, 320 bytes).
pub const RED_LEN: usize = 40;

/// Table stride in u64 words for `scatter4`/`gather4` (128 bytes per limb).
pub const SCATTER4_STRIDE: usize = 16;

/// Table span in u64 words for `scatter5`/`gather5` (9 groups * 512 bytes).
pub const SCATTER5_WORDS: usize = 576;

/// `out = a^2` Montgomery-squared `times` times modulo `n`.
///
/// One iteration computes `a^2 * R^-1 mod n` with R = 2^512; feeding the
/// output back in keeps the value in Montgomery form, matching the
/// square-and-multiply loop in `RSAZ_512_mod_exp`.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn sqr_512(out: &mut [u64], a: &[u64], n: &[u64], n0: u64, times: u32) {
    debug_assert_eq!(out.len(), LIMBS_512);
    debug_assert_eq!(a.len(), LIMBS_512);
    debug_assert_eq!(n.len(), LIMBS_512);
    unsafe {
        rsaz_512_sqr(out.as_mut_ptr(), a.as_ptr(), n.as_ptr(), n0, times as i32);
    }
}

/// `out = a * b * R^-1 mod n` with R = 2^512 (Montgomery multiplication).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn mul_512(out: &mut [u64], a: &[u64], b: &[u64], n: &[u64], n0: u64) {
    debug_assert_eq!(out.len(), LIMBS_512);
    debug_assert_eq!(a.len(), LIMBS_512);
    debug_assert_eq!(b.len(), LIMBS_512);
    debug_assert_eq!(n.len(), LIMBS_512);
    unsafe {
        rsaz_512_mul(out.as_mut_ptr(), a.as_ptr(), b.as_ptr(), n.as_ptr(), n0);
    }
}

/// `out = a * R^-1 mod n` (Montgomery reduction by the constant 1).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn mul_by_one_512(out: &mut [u64], a: &[u64], n: &[u64], n0: u64) {
    debug_assert_eq!(out.len(), LIMBS_512);
    debug_assert_eq!(a.len(), LIMBS_512);
    debug_assert_eq!(n.len(), LIMBS_512);
    unsafe {
        rsaz_512_mul_by_one(out.as_mut_ptr(), a.as_ptr(), n.as_ptr(), n0);
    }
}

/// `out = a * tbl[power] * R^-1 mod n`, gathering from a scattered table.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn mul_gather4_512(out: &mut [u64], a: &[u64], tbl: &[u64], n: &[u64], n0: u64, power: u32) {
    debug_assert_eq!(out.len(), LIMBS_512);
    debug_assert_eq!(a.len(), LIMBS_512);
    debug_assert_eq!(n.len(), LIMBS_512);
    debug_assert!(tbl.len() >= SCATTER4_STRIDE * LIMBS_512);
    unsafe {
        rsaz_512_mul_gather4(
            out.as_mut_ptr(),
            a.as_ptr(),
            tbl.as_ptr(),
            n.as_ptr(),
            n0,
            power,
        );
    }
}

/// `out = a * out * R^-1 mod n` (reading `out` as the multiplicand) and
/// scattering the result as table entry `power`. Used to build successive
/// powers of `a` in the scattered window table.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn mul_scatter4_512(
    out: &mut [u64],
    a: &[u64],
    n: &[u64],
    n0: u64,
    tbl: &mut [u64],
    power: u32,
) {
    debug_assert_eq!(out.len(), LIMBS_512);
    debug_assert_eq!(a.len(), LIMBS_512);
    debug_assert_eq!(n.len(), LIMBS_512);
    debug_assert!(tbl.len() >= SCATTER4_STRIDE * LIMBS_512);
    unsafe {
        rsaz_512_mul_scatter4(
            out.as_mut_ptr(),
            a.as_ptr(),
            n.as_ptr(),
            n0,
            tbl.as_mut_ptr(),
            power,
        );
    }
}

/// Store `val` as table entry `power`. Layout is structure-of-arrays:
/// limb `i` of entry `power` lives at `tbl[power + i * 16]`.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn scatter4_512(tbl: &mut [u64], val: &[u64], power: u32) {
    debug_assert_eq!(val.len(), LIMBS_512);
    debug_assert!(tbl.len() >= SCATTER4_STRIDE * LIMBS_512);
    debug_assert!(power < SCATTER4_STRIDE as u32);
    unsafe {
        rsaz_512_scatter4(tbl.as_mut_ptr(), val.as_ptr(), power as i32);
    }
}

/// Load table entry `power` into `val` (inverse of [`scatter4_512`]).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn gather4_512(val: &mut [u64], tbl: &[u64], power: u32) {
    debug_assert_eq!(val.len(), LIMBS_512);
    debug_assert!(tbl.len() >= SCATTER4_STRIDE * LIMBS_512);
    debug_assert!(power < SCATTER4_STRIDE as u32);
    unsafe {
        rsaz_512_gather4(val.as_mut_ptr(), tbl.as_ptr(), power as i32);
    }
}

/// `rp = ap * bp * R^-1 mod np` in the 29-bit-digit redundant form
/// (R = 2^1044). All four buffers are [`RED_LEN`] words.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn mul_1024_avx2(out: &mut [u64], a: &[u64], b: &[u64], n: &[u64], n0: u64) {
    debug_assert_eq!(out.len(), RED_LEN);
    debug_assert_eq!(a.len(), RED_LEN);
    debug_assert_eq!(b.len(), RED_LEN);
    debug_assert_eq!(n.len(), RED_LEN);
    unsafe {
        rsaz_1024_mul_avx2(out.as_mut_ptr(), a.as_ptr(), b.as_ptr(), n.as_ptr(), n0);
    }
}

/// `rp = ap^(2^rep) * R^-(2^rep - 1) mod np` — `rep` successive Montgomery
/// squarings in the redundant form.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn sqr_1024_avx2(out: &mut [u64], a: &[u64], n: &[u64], n0: u64, rep: u32) {
    debug_assert_eq!(out.len(), RED_LEN);
    debug_assert_eq!(a.len(), RED_LEN);
    debug_assert_eq!(n.len(), RED_LEN);
    unsafe {
        rsaz_1024_sqr_avx2(out.as_mut_ptr(), a.as_ptr(), n.as_ptr(), n0, rep as i32);
    }
}

/// Convert a normal 16-limb little-endian value into the 40-word
/// 29-bit-digit redundant form.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn norm2red_1024(red: &mut [u64], norm: &[u64]) {
    debug_assert_eq!(red.len(), RED_LEN);
    debug_assert_eq!(norm.len(), LIMBS_1024);
    unsafe {
        rsaz_1024_norm2red_avx2(red.as_mut_ptr(), norm.as_ptr());
    }
}

/// Convert a 40-word redundant-form value back to 16 normal limbs.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn red2norm_1024(norm: &mut [u64], red: &[u64]) {
    debug_assert_eq!(norm.len(), LIMBS_1024);
    debug_assert_eq!(red.len(), RED_LEN);
    unsafe {
        rsaz_1024_red2norm_avx2(norm.as_mut_ptr(), red.as_ptr());
    }
}

/// Store redundant-form `val` as scatter5 table entry `i` (0..32).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn scatter5_1024_avx2(tbl: &mut [u64], val: &[u64], i: u32) {
    debug_assert_eq!(val.len(), RED_LEN);
    debug_assert!(tbl.len() >= SCATTER5_WORDS);
    debug_assert!(i < 32);
    unsafe {
        rsaz_1024_scatter5_avx2(tbl.as_mut_ptr(), val.as_ptr(), i as i32);
    }
}

/// Load scatter5 table entry `i` into `val` (inverse of [`scatter5_1024_avx2`]).
///
/// The table buffer must be 32-byte aligned: the routine loads it with
/// `vmovdqa` (OpenSSL 64-byte-aligns its storage).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn gather5_1024_avx2(val: &mut [u64], tbl: &[u64], i: u32) {
    debug_assert_eq!(val.len(), RED_LEN);
    debug_assert!(tbl.len() >= SCATTER5_WORDS);
    debug_assert!(i < 32);
    debug_assert_eq!(
        tbl.as_ptr() as usize % 32,
        0,
        "rsaz_1024_gather5_avx2 table must be 32-byte aligned"
    );
    unsafe {
        rsaz_1024_gather5_avx2(val.as_mut_ptr(), tbl.as_ptr(), i as i32);
    }
}

/// True when the CPU exposes the AVX2 + BMI2 bits `rsaz_avx2_eligible`
/// requires (OPENSSL_ia32cap_P+8 & 0x80100 == 0x80100 and AVX2 bit 5).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub fn avx2_eligible() -> bool {
    unsafe { rsaz_avx2_eligible() != 0 }
}
