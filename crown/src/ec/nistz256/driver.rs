//! Windowed P-256 scalar multiplication driving the nistz256 assembly.
//!
//! This is the Rust port of the drivers in OpenSSL's
//! `crypto/ec/ecp_nistz256.c`:
//!
//! - [`mul`] is `ecp_nistz256_windowed_mul`: a 5-bit Booth-recode windowed
//!   ladder over a scatter/gather table of 16 Jacobian points.
//! - [`mul_base`] uses the statically precomputed 7-bit generator table
//!   (`ecp_nistz256_precomputed`, 37 rows of 64 affine points) that the
//!   perlasm module carries in `.rodata`.
//!
//! Both are constant-time with respect to the scalar apart from the final
//! affine conversion, which inverts Z with the software modular inverse,
//! matching OpenSSL's own use of the public-output path.
//!
//! Field elements are 4 little-endian `u64` limbs in Montgomery form, the
//! same layout as [`crate::bn::Bn`] and the assembly; Jacobian points are
//! three contiguous field elements (12 limbs).

use crate::bn::Bn;
use crate::ec::{Curve, Point};

use super::asm;

const LIMBS: usize = 4;
type Fe = [u64; LIMBS];
type Jac = [u64; 12];

/// The P-256 prime `2^256 - 2^224 + 2^192 + 2^96 - 1` in little-endian
/// limbs, used to recognise the curve.
const P256_P: [u64; LIMBS] = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
];

/// `OPENSSL_ia32cap_P`-independent feature check: the caller has to pass a
/// real P-256 curve (SM2 shares the limb count and must stay on the
/// software path).
pub(crate) fn is_p256(c: &Curve) -> bool {
    c.p.limbs == P256_P
}

/// 64-byte aligned w5 table storage; the gather routines use unaligned
/// loads, but keeping the table aligned costs nothing.
#[repr(align(64))]
struct W5Table([u64; 16 * 12]);

/// `ecp_nistz256_scatter_w5` loads its input with `movdqa`, so the point
/// has to be 16-byte aligned.
#[repr(align(16))]
struct AlignedPoint([u64; 12]);

fn scatter_w5(table: &mut [u64], point: &[u64; 12], index: i32) {
    let aligned = AlignedPoint(*point);
    asm::scatter_w5(table, &aligned.0, index);
}

fn limbs_of(v: &Bn) -> Fe {
    let mut out = [0u64; LIMBS];
    for (slot, &limb) in out.iter_mut().zip(v.limbs.iter()) {
        *slot = limb;
    }
    out
}

fn bn_of(limbs: Fe) -> Bn {
    let mut bn = Bn {
        limbs: alloc::vec::Vec::from(limbs),
    };
    bn.normalize();
    bn
}

fn p_bn() -> Bn {
    bn_of(P256_P)
}

/// Affine point (plain domain) to Montgomery Jacobian `(X : Y : R)`.
fn to_jac(p: &Point) -> Jac {
    if p.infinity {
        return [0u64; 12];
    }
    let mut out = [0u64; 12];
    out[0..4].copy_from_slice(&asm::to_mont(&limbs_of(&p.x)));
    out[4..8].copy_from_slice(&asm::to_mont(&limbs_of(&p.y)));
    // Z = R mod p (one in the Montgomery domain).
    let mut one = [0u64; LIMBS];
    one[0] = 1;
    out[8..12].copy_from_slice(&asm::to_mont(&one));
    out
}

/// Montgomery Jacobian to an affine point, leaving the Montgomery domain.
fn from_jac(j: &Jac) -> Option<Point> {
    if j[8..12].iter().all(|&limb| limb == 0) {
        return Some(Point::infinity());
    }
    let p = p_bn();
    let x = bn_of(asm::from_mont(j[0..4].try_into().ok()?));
    let y = bn_of(asm::from_mont(j[4..8].try_into().ok()?));
    let z = bn_of(asm::from_mont(j[8..12].try_into().ok()?));
    if z.is_zero() {
        return Some(Point::infinity());
    }
    let z_inv = z.mod_inverse(&p).ok()?;
    let z_inv2 = z_inv.modmul(&z_inv, &p);
    let z_inv3 = z_inv2.modmul(&z_inv, &p);
    Some(Point {
        x: x.modmul(&z_inv2, &p),
        y: y.modmul(&z_inv3, &p),
        infinity: false,
    })
}

/// Conditional move: `dst = src` when `movement == 1`, constant time.
fn copy_conditional(dst: &mut [u64], src: &[u64], movement: u64) {
    let mask1 = movement.wrapping_neg();
    let mask2 = !mask1;
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = (s & mask1) ^ (*d & mask2);
    }
}

/// Booth recode a 5-bit window.
fn booth_recode_w5(input: u32) -> u32 {
    let s = !((input >> 5).wrapping_sub(1));
    let mut d = (1 << 6) - input - 1;
    d = (d & s) | (input & !s);
    d = (d >> 1) + (d & 1);
    (d << 1) + (s & 1)
}

/// Booth recode a 7-bit window.
fn booth_recode_w7(input: u32) -> u32 {
    let s = !((input >> 7).wrapping_sub(1));
    let mut d = (1 << 8) - input - 1;
    d = (d & s) | (input & !s);
    d = (d >> 1) + (d & 1);
    (d << 1) + (s & 1)
}

/// The scalar as 33 little-endian bytes (scalars are reduced below `n`
/// first, so 32 bytes plus a zero guard suffice).
fn scalar_bytes(k: &Bn) -> Option<[u8; 33]> {
    let be = k.to_be_bytes_padded(32).ok()?;
    let mut out = [0u8; 33];
    for (i, &_byte) in be.iter().enumerate() {
        out[i] = be[31 - i];
    }
    Some(out)
}

/// `k * p` on P-256 (windowed, w5).
pub(crate) fn mul(p: &Point, k: &Bn, n: &Bn) -> Option<Point> {
    let k = k.modulus(n);
    if k.is_zero() || p.infinity {
        return Some(Point::infinity());
    }
    let scalar = scalar_bytes(&k)?;
    let base = to_jac(p);

    // table[i - 1] = i * P for i in 1..=16, built with the assembly point
    // ops and scattered constant-time.
    let mut table = W5Table([0u64; 16 * 12]);
    scatter_w5(&mut table.0, &base, 1);
    let t1 = asm::point_double(&base);
    scatter_w5(&mut table.0, &t1, 2);
    let t2 = asm::point_add(&t1, &base);
    scatter_w5(&mut table.0, &t2, 3);
    let t1 = asm::point_double(&t1);
    scatter_w5(&mut table.0, &t1, 4);
    let t2 = asm::point_double(&t2);
    scatter_w5(&mut table.0, &t2, 6);
    let t3 = asm::point_add(&t1, &base);
    scatter_w5(&mut table.0, &t3, 5);
    let t4 = asm::point_add(&t2, &base);
    scatter_w5(&mut table.0, &t4, 7);
    let t1 = asm::point_double(&t1);
    scatter_w5(&mut table.0, &t1, 8);
    let t2 = asm::point_double(&t2);
    scatter_w5(&mut table.0, &t2, 12);
    let t3 = asm::point_double(&t3);
    scatter_w5(&mut table.0, &t3, 10);
    let t4 = asm::point_double(&t4);
    scatter_w5(&mut table.0, &t4, 14);
    let t2 = asm::point_add(&t2, &base);
    scatter_w5(&mut table.0, &t2, 13);
    let t3 = asm::point_add(&t3, &base);
    scatter_w5(&mut table.0, &t3, 11);
    let t4 = asm::point_add(&t4, &base);
    scatter_w5(&mut table.0, &t4, 15);
    let t2 = asm::point_add(&t1, &base);
    scatter_w5(&mut table.0, &t2, 9);
    let t1 = asm::point_double(&t1);
    scatter_w5(&mut table.0, &t1, 16);

    // First window (bits 255..250).
    let mut index = 255u32;
    let mut wvalue = (scalar[((index - 1) / 8) as usize] as u32 >> ((index - 1) % 8)) & 0x3f;
    wvalue = booth_recode_w5(wvalue);
    let mut r = [0u64; 12];
    asm::gather_w5(&mut r, &table.0, (wvalue >> 1) as i32);
    let neg_y = asm::neg(&r[4..8].try_into().ok()?);
    copy_conditional(&mut r[4..8], &neg_y, (wvalue & 1) as u64);

    while index >= 5 {
        // The first window was already folded in above (idx == 255).
        if index != 255 {
            let offset = ((index - 1) / 8) as usize;
            let mut wvalue =
                (scalar[offset] as u32 | (scalar[offset + 1] as u32) << 8) >> ((index - 1) % 8);
            wvalue &= 0x3f;
            wvalue = booth_recode_w5(wvalue);
            let mut t = [0u64; 12];
            asm::gather_w5(&mut t, &table.0, (wvalue >> 1) as i32);
            let neg_y = asm::neg(&t[4..8].try_into().ok()?);
            copy_conditional(&mut t[4..8], &neg_y, (wvalue & 1) as u64);
            r = asm::point_add(&r, &t);
        }

        index -= 5;
        for _ in 0..5 {
            r = asm::point_double(&r);
        }
    }

    // Final window.
    let mut wvalue = ((scalar[0] as u32) << 1) & 0x3f;
    wvalue = booth_recode_w5(wvalue);
    let mut t = [0u64; 12];
    asm::gather_w5(&mut t, &table.0, (wvalue >> 1) as i32);
    let neg_y = asm::neg(&t[4..8].try_into().ok()?);
    copy_conditional(&mut t[4..8], &neg_y, (wvalue & 1) as u64);
    r = asm::point_add(&r, &t);

    from_jac(&r)
}

extern "C" {
    /// The 37 × 64 affine generator multiples emitted by
    /// `ecp_nistz256-x86_64.pl` (151 552 bytes).
    static ecp_nistz256_precomputed: [u64; 37 * 512];
}

/// Test hook: a row of the precomputed generator table.
#[cfg(test)]
pub(crate) fn precomputed_row_for_test(i: usize) -> &'static [u64] {
    let table = core::ptr::addr_of!(ecp_nistz256_precomputed);
    unsafe { core::slice::from_raw_parts(table.cast::<u64>().add(i * 512), 512) }
}

/// Test hook: affine to Montgomery Jacobian.
#[cfg(test)]
pub(crate) fn to_jac_for_test(p: &Point) -> Jac {
    to_jac(p)
}

/// `k * G` on P-256 using the precomputed generator table (w7).
pub(crate) fn mul_base(k: &Bn, n: &Bn) -> Option<Point> {
    let k = k.modulus(n);
    if k.is_zero() {
        return Some(Point::infinity());
    }
    let scalar = scalar_bytes(&k)?;
    let table = core::ptr::addr_of!(ecp_nistz256_precomputed);
    let row = |i: usize| -> &'static [u64] {
        // SAFETY: the symbol is a static blob of 37 * 512 u64 emitted by
        // the assembly; each row is 64 affine points of 8 limbs.
        unsafe { core::slice::from_raw_parts(table.cast::<u64>().add(i * 512), 512) }
    };

    // First window (bits 255..249).
    let mut wvalue = ((scalar[0] as u32) << 1) & 0xff;
    wvalue = booth_recode_w7(wvalue);
    let mut p = [0u64; 12];
    let mut first = [0u64; 8];
    asm::gather_w7(&mut first, row(0), (wvalue >> 1) as i32);
    p[0..8].copy_from_slice(&first);
    let neg_y = asm::neg(&p[4..8].try_into().ok()?);
    copy_conditional(&mut p[4..8], &neg_y, (wvalue & 1) as u64);
    // Affine infinity is (0, 0); Jacobian infinity is Z = 0. Use one as Z
    // for the live point, zero for infinity.
    let mut one = [0u64; LIMBS];
    one[0] = 1;
    let one_m = asm::to_mont(&one);
    let infty = p[0..8].iter().fold(0u64, |acc, &limb| acc | limb);
    // All ones when the gathered point is not the implicit infinity, zero
    // when it is (constant time).
    let mask = !((infty == 0) as u64).wrapping_neg();
    for (i, &limb) in one_m.iter().enumerate() {
        p[8 + i] = limb & mask;
    }

    let mut index = 7u32;
    for i in 1..37 {
        let offset = ((index - 1) / 8) as usize;
        let mut wvalue =
            (scalar[offset] as u32 | (scalar[offset + 1] as u32) << 8) >> ((index - 1) % 8);
        wvalue &= 0xff;
        index += 7;
        wvalue = booth_recode_w7(wvalue);
        let mut t = [0u64; 8];
        asm::gather_w7(&mut t, row(i), (wvalue >> 1) as i32);
        let neg_y = asm::neg(&t[4..8].try_into().ok()?);
        copy_conditional(&mut t[4..8], &neg_y, (wvalue & 1) as u64);
        p = asm::point_add_affine(&p, &t);
    }
    from_jac(&p)
}
