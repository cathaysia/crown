#![allow(dead_code, unused_mut, unused_imports)]
//! RSAZ assembly helpers (rsaz-x86_64.pl / rsaz-avx2.pl) for x86_64.
//!
//! OpenSSL's `crypto/bn/asm/rsaz-x86_64.pl` provides 512-bit Montgomery
//! primitives (R = 2^512, 8 limbs) used by `RSAZ_512_mod_exp`, and
//! `crypto/bn/asm/rsaz-avx2.pl` provides the 1024-bit AVX2 family used by
//! `RSAZ_1024_mod_exp_avx2`. Both are translated, exported, unit-tested
//! and dispatched: [`mod_exp`] ports `crypto/bn/rsaz_exp.c` and
//! [`crate::bn::Montgomery::pow_consttime`] routes 512- and 1024-bit
//! moduli (RSA-1024/2048 CRT halves) through it, falling back to the mont5
//! `bn_mul_mont`/`bn_power5` stack for everything else.
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

// ---------------------------------------------------------------------------
// Drivers: ports of crypto/bn/rsaz_exp.c
// ---------------------------------------------------------------------------

use crate::bn::{Bn, Montgomery};
use alloc::vec::Vec;

/// 64-byte aligned scratch storage for the scatter tables.
#[repr(align(64))]
struct Aligned<const N: usize>([u64; N]);

/// Widen `v` to `num` limbs.
fn pad(v: &Bn, num: usize) -> Vec<u64> {
    let mut out = alloc::vec![0u64; num];
    for (slot, &limb) in out.iter_mut().zip(v.limbs.iter()) {
        *slot = limb;
    }
    out
}

/// Conditional subtract of `m` once, for results below `2*m`.
fn reduce_once(v: &mut [u64], m: &[u64]) {
    let mut ge = true;
    for (a, b) in v.iter().zip(m.iter()).rev() {
        if a != b {
            ge = a > b;
            break;
        }
    }
    if ge {
        let mut borrow = 0u64;
        for (a, &b) in v.iter_mut().zip(m.iter()) {
            let (d1, b1) = a.overflowing_sub(b);
            let (d2, b2) = d1.overflowing_sub(borrow);
            *a = d2;
            borrow = (b1 as u64) | (b2 as u64);
        }
    }
}

/// RSAZ-backed `a^e mod n` returned in Montgomery form, matching
/// [`Montgomery::pow_consttime`]'s contract.
///
/// Returns `None` when the modulus size or CPU features do not apply, so
/// the caller falls back to the mont5 stack.
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub(crate) fn mod_exp(mont: &Montgomery, a_mont: &Bn, e: &Bn) -> Option<Bn> {
    let num = mont.limbs;
    if !matches!(num, LIMBS_512 | LIMBS_1024) {
        return None;
    }
    if num == LIMBS_1024 && !avx2_eligible() {
        return None;
    }
    if e.is_zero() {
        return Some(mont.to_mont(&Bn::one()));
    }
    // RSAZ takes the base in the normal domain.
    let a_norm = mont.from_mont(a_mont);
    let base = pad(&a_norm, num);
    let exponent = pad(e, num);
    let m = pad(&mont.n, num);
    let rr = pad(&mont.r2, num);
    let n0 = mont.n0;
    let normal: Vec<u64> = if num == LIMBS_512 {
        let mut b = [0u64; LIMBS_512];
        let mut x = [0u64; LIMBS_512];
        let mut md = [0u64; LIMBS_512];
        let mut r = [0u64; LIMBS_512];
        b.copy_from_slice(&base);
        x.copy_from_slice(&exponent);
        md.copy_from_slice(&m);
        r.copy_from_slice(&rr);
        mod_exp_512(&b, &x, &md, n0, &r).to_vec()
    } else {
        let mut b = [0u64; LIMBS_1024];
        let mut x = [0u64; LIMBS_1024];
        let mut md = [0u64; LIMBS_1024];
        let mut r = [0u64; LIMBS_1024];
        b.copy_from_slice(&base);
        x.copy_from_slice(&exponent);
        md.copy_from_slice(&m);
        r.copy_from_slice(&rr);
        mod_exp_1024(&b, &x, &md, n0, &r).to_vec()
    };
    let mut result = Bn { limbs: normal };
    result.normalize();
    if !result.lt(&mont.n) {
        result = result.sub(&mont.n).unwrap_or(result);
    }
    Some(mont.to_mont(&result))
}

/// `RSAZ_512_mod_exp` (R = 2^512).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
fn mod_exp_512(
    base: &[u64; LIMBS_512],
    exponent: &[u64; LIMBS_512],
    m: &[u64; LIMBS_512],
    n0: u64,
    rr: &[u64; LIMBS_512],
) -> [u64; LIMBS_512] {
    let mut table = Aligned::<{ 16 * LIMBS_512 }>([0u64; 16 * LIMBS_512]);
    let mut a_inv = [0u64; LIMBS_512];
    let mut temp = [0u64; LIMBS_512];

    // table[0] = R mod m = -m
    let mut minus_m = [0u64; LIMBS_512];
    minus_m[0] = 0u64.wrapping_sub(m[0]);
    for i in 1..LIMBS_512 {
        minus_m[i] = !m[i];
    }
    scatter4_512(&mut table.0, &minus_m, 0);

    // table[1] = base * R
    mul_512(&mut a_inv, base, rr, m, n0);
    scatter4_512(&mut table.0, &a_inv, 1);

    // table[2] = (base * R)^2 / R
    let a_owned = a_inv;
    sqr_512(&mut temp, &a_owned, m, n0, 1);
    scatter4_512(&mut table.0, &temp, 2);

    // table[3..16]
    for index in 3..16u32 {
        let a_owned = a_inv;
        mul_scatter4_512(&mut temp, &a_owned, m, n0, &mut table.0, index);
    }

    let mut bytes = [0u8; 64];
    for (i, &limb) in exponent.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }

    let mut wvalue = bytes[63];
    gather4_512(&mut temp, &table.0, u32::from(wvalue >> 4));
    let t_owned = temp;
    sqr_512(&mut temp, &t_owned, m, n0, 4);
    let t_owned = temp;
    mul_gather4_512(
        &mut temp,
        &t_owned,
        &table.0,
        m,
        n0,
        u32::from(wvalue & 0x0f),
    );

    for index in (0..=62).rev() {
        wvalue = bytes[index];
        let t_owned = temp;
        sqr_512(&mut temp, &t_owned, m, n0, 4);
        let t_owned = temp;
        mul_gather4_512(&mut temp, &t_owned, &table.0, m, n0, u32::from(wvalue >> 4));
        let t_owned = temp;
        sqr_512(&mut temp, &t_owned, m, n0, 4);
        let t_owned = temp;
        mul_gather4_512(
            &mut temp,
            &t_owned,
            &table.0,
            m,
            n0,
            u32::from(wvalue & 0x0f),
        );
    }

    let t_owned = temp;
    mul_by_one_512(&mut temp, &t_owned, m, n0);
    reduce_once(&mut temp, m);
    temp
}

/// `RSAZ_1024_mod_exp_avx2` (AMM R = 2^1044, redundant 29-bit digits).
#[cfg(all(feature = "asm", target_arch = "x86_64"))]
fn mod_exp_1024(
    base: &[u64; LIMBS_1024],
    exponent: &[u64; LIMBS_1024],
    m: &[u64; LIMBS_1024],
    n0: u64,
    rr: &[u64; LIMBS_1024],
) -> [u64; LIMBS_1024] {
    let mut m_red = [0u64; RED_LEN];
    norm2red_1024(&mut m_red, m);
    let mut a_red = [0u64; RED_LEN];
    norm2red_1024(&mut a_red, base);
    let mut r2_red = [0u64; RED_LEN];
    norm2red_1024(&mut r2_red, rr);

    let mut one = [0u64; RED_LEN];
    one[0] = 1;
    let mut two80 = [0u64; RED_LEN];
    two80[2] = 1 << 22;

    let mut table = Aligned::<SCATTER5_WORDS>([0u64; SCATTER5_WORDS]);
    let mut result = [0u64; RED_LEN];
    let mut a_inv = [0u64; RED_LEN];

    // R2 = RR^2 * 2^80 (bridges 2^1024 and the AMM's 2^1044).
    let x = r2_red;
    mul_1024_avx2(&mut r2_red, &x, &x, &m_red, n0);
    let x = r2_red;
    mul_1024_avx2(&mut r2_red, &x, &two80, &m_red, n0);

    macro_rules! sqr_into {
        ($out:expr, $a:expr) => {{
            let a = $a;
            sqr_1024_avx2(&mut $out, &a, &m_red, n0, 1);
        }};
    }
    macro_rules! mul_into {
        ($out:expr, $a:expr, $b:expr) => {{
            let a = $a;
            let b = $b;
            mul_1024_avx2(&mut $out, &a, &b, &m_red, n0);
        }};
    }
    macro_rules! scatter {
        ($val:expr, $i:expr) => {{
            let v = $val;
            scatter5_1024_avx2(&mut table.0, &v, $i);
        }};
    }
    macro_rules! gather {
        ($val:expr, $i:expr) => {{
            gather5_1024_avx2(&mut $val, &table.0, $i);
        }};
    }

    // table[0] = one (R_amm mod m), table[1] = base * R_amm.
    mul_into!(result, r2_red, one);
    scatter!(result, 0);
    mul_into!(a_inv, a_red, r2_red);
    scatter!(a_inv, 1);

    sqr_into!(result, a_inv);
    scatter!(result, 2);
    sqr_into!(result, result);
    scatter!(result, 4);
    sqr_into!(result, result);
    scatter!(result, 8);
    sqr_into!(result, result);
    scatter!(result, 16);
    mul_into!(result, result, a_inv);
    scatter!(result, 17);

    gather!(result, 2);
    mul_into!(result, result, a_inv);
    scatter!(result, 3);
    sqr_into!(result, result);
    scatter!(result, 6);
    sqr_into!(result, result);
    scatter!(result, 12);
    sqr_into!(result, result);
    scatter!(result, 24);
    mul_into!(result, result, a_inv);
    scatter!(result, 25);

    gather!(result, 4);
    mul_into!(result, result, a_inv);
    scatter!(result, 5);
    sqr_into!(result, result);
    scatter!(result, 10);
    sqr_into!(result, result);
    scatter!(result, 20);
    mul_into!(result, result, a_inv);
    scatter!(result, 21);

    gather!(result, 6);
    mul_into!(result, result, a_inv);
    scatter!(result, 7);
    sqr_into!(result, result);
    scatter!(result, 14);
    sqr_into!(result, result);
    scatter!(result, 28);
    mul_into!(result, result, a_inv);
    scatter!(result, 29);

    gather!(result, 8);
    mul_into!(result, result, a_inv);
    scatter!(result, 9);
    sqr_into!(result, result);
    scatter!(result, 18);
    mul_into!(result, result, a_inv);
    scatter!(result, 19);

    gather!(result, 10);
    mul_into!(result, result, a_inv);
    scatter!(result, 11);
    sqr_into!(result, result);
    scatter!(result, 22);
    mul_into!(result, result, a_inv);
    scatter!(result, 23);

    gather!(result, 12);
    mul_into!(result, result, a_inv);
    scatter!(result, 13);
    sqr_into!(result, result);
    scatter!(result, 26);
    mul_into!(result, result, a_inv);
    scatter!(result, 27);

    gather!(result, 14);
    mul_into!(result, result, a_inv);
    scatter!(result, 15);
    sqr_into!(result, result);
    scatter!(result, 30);
    mul_into!(result, result, a_inv);
    scatter!(result, 31);

    // First window: the top 8 bits of the exponent.
    let mut bytes = [0u8; 128];
    for (i, &limb) in exponent.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    let mut wvalue = u32::from(bytes[127] >> 3);
    gather!(result, wvalue);

    let mut index: i32 = 1014;
    while index > -1 {
        let r_owned = result;
        sqr_1024_avx2(&mut result, &r_owned, &m_red, n0, 5);
        let low = bytes[(index / 8) as usize] as u32;
        let high = bytes[(index / 8 + 1) as usize] as u32;
        wvalue = ((high << 8) | low) >> (index % 8) & 31;
        index -= 5;
        gather!(a_inv, wvalue);
        mul_into!(result, result, a_inv);
    }

    let r_owned = result;
    sqr_1024_avx2(&mut result, &r_owned, &m_red, n0, 4);
    wvalue = u32::from(bytes[0] & 15);
    gather!(a_inv, wvalue);
    mul_into!(result, result, a_inv);

    // Leave Montgomery form; `one` acts as the AMM's 1.
    mul_into!(result, result, one);

    let mut normal = [0u64; LIMBS_1024];
    red2norm_1024(&mut normal, &result);
    reduce_once(&mut normal, m);
    normal
}
