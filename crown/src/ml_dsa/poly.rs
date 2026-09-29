//! Polynomial arithmetic and coefficient compression for ML-DSA.

use super::ntt::{mod_sub, reduce_once};
use super::params::{D_BITS, N, Q, Q_MINUS1_DIV2, GAMMA2_Q_MINUS1_DIV32};

/// A degree-255 polynomial over Z_q; coefficients are stored in `0..q`.
#[derive(Clone)]
pub(crate) struct Poly {
    pub coeff: [u32; N],
}

impl Poly {
    pub fn zero() -> Self {
        Poly { coeff: [0; N] }
    }
}

/// `p += q` (elementwise), reducing into `0..q`.
pub(crate) fn poly_add(a: &Poly, b: &Poly, out: &mut Poly) {
    for i in 0..N {
        out.coeff[i] = reduce_once(a.coeff[i] as u64 + b.coeff[i] as u64);
    }
}

/// `out = a - b` in `0..q` (FIPS 204 keeps signed representatives; OpenSSL
/// stores the positive form `q - x` for negative coefficients).
pub(crate) fn poly_sub(a: &Poly, b: &Poly, out: &mut Poly) {
    for i in 0..N {
        out.coeff[i] = mod_sub(a.coeff[i], b.coeff[i]);
    }
}

/// FIPS 204 Algorithm 35 `Power2Round`: `r = r1 * 2^13 + r0 (mod q)`.
///
/// `r0` is kept as a non-negative residue (`q - |r0|` when negative).
pub(crate) fn power2_round(r: u32) -> (u32, u32) {
    let mut r1 = r >> D_BITS;
    let mut r0 = r - (r1 << D_BITS);
    // If r0 > 2^12, shift one 2^13 into r1 and make r0 negative (as q - x).
    let mask = (((1u32 << (D_BITS - 1)) < r0) as u32).wrapping_neg();
    let r0_adj = mod_sub(r0, 1 << D_BITS);
    let r1_adj = r1 + 1;
    r0 = (r0 & !mask) | (r0_adj & mask);
    r1 = (r1 & !mask) | (r1_adj & mask);
    (r1, r0)
}

/// FIPS 204 Algorithm 37 `HighBits`.
pub(crate) fn high_bits(r: u32, gamma2: u32) -> u32 {
    let mut r1 = ((r + 127) >> 7) as i32;
    if gamma2 == GAMMA2_Q_MINUS1_DIV32 {
        r1 = (r1 * 1025 + (1 << 21)) >> 22;
        (r1 & 15) as u32
    } else {
        r1 = (r1 * 11275 + (1 << 23)) >> 24;
        // Zero r1 when it would exceed 43.
        let mask = ((43 - r1) >> 31) as u32;
        (r1 as u32) ^ (mask & (r1 as u32))
    }
}

/// FIPS 204 Algorithm 36 `Decompose`: returns `(r1, r0)` with
/// `r = r1 * 2 * gamma2 + r0 (mod q)`. `r0` is a signed representative
/// centred around 0.
pub(crate) fn decompose(r: u32, gamma2: u32) -> (u32, i32) {
    let r1 = high_bits(r, gamma2);
    let mut r0 = r as i32 - (r1 as i32) * 2 * (gamma2 as i32);
    // Fold into (-q/2, q/2].
    let borrow = ((Q_MINUS1_DIV2 as i32 - r0) >> 31) & (Q as i32);
    r0 -= borrow;
    (r1, r0)
}

/// FIPS 204 Algorithm 38 `LowBits`.
pub(crate) fn low_bits(r: u32, gamma2: u32) -> i32 {
    decompose(r, gamma2).1
}

/// FIPS 204 Algorithm 39 `MakeHint`.
///
/// OpenSSL folds the two `HighBits` calls into one expression by passing
/// `z = -ct0` and `r = w - cs2 + ct0`; here `r_plus_z = w - cs2` and
/// `r = r_plus_z + ct0`.
pub(crate) fn make_hint(ct0: u32, cs2: u32, gamma2: u32, w: u32) -> u32 {
    let r_plus_z = mod_sub(w, cs2);
    let r = reduce_once(r_plus_z as u64 + ct0 as u64);
    (high_bits(r, gamma2) != high_bits(r_plus_z, gamma2)) as u32
}

/// FIPS 204 Algorithm 40 `UseHint`.
pub(crate) fn use_hint(hint: u32, r: u32, gamma2: u32) -> u32 {
    let (r1, r0) = decompose(r, gamma2);
    if hint == 0 {
        return r1;
    }
    if gamma2 == GAMMA2_Q_MINUS1_DIV32 {
        if r0 > 0 {
            (r1 + 1) & 15
        } else {
            (r1.wrapping_sub(1)) & 15
        }
    } else if r0 > 0 {
        if r1 == 43 {
            0
        } else {
            r1 + 1
        }
    } else if r1 == 0 {
        43
    } else {
        r1 - 1
    }
}

/// Maximum `|coeff| mod q` (centred absolute value) over a polynomial.
pub(crate) fn poly_max_mod(p: &Poly) -> u32 {
    let mut mx = 0u32;
    for &c in &p.coeff {
        let abs = if c > Q_MINUS1_DIV2 { Q - c } else { c };
        if abs > mx {
            mx = abs;
        }
    }
    mx
}

/// Maximum absolute value over a polynomial whose coefficients are signed
/// values stored as two's complement in a `u32` (used for `r0`).
pub(crate) fn poly_max_signed(p: &Poly) -> u32 {
    let mut mx = 0u32;
    for &c in &p.coeff {
        let abs = if (c as i32) < 0 {
            c.wrapping_neg()
        } else {
            c
        };
        if abs > mx {
            mx = abs;
        }
    }
    mx
}

/// Sum of coefficients (hint polynomials only contain 0/1).
pub(crate) fn poly_count_ones(p: &Poly) -> usize {
    p.coeff.iter().map(|&c| c as usize).sum()
}
