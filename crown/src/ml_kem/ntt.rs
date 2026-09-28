//! Number-theoretic transform and polynomial arithmetic over R_q = Z_q[X]/(X^256 + 1).
//!
//! FIPS 203 §4.3: incomplete NTT of degree 256 with q = 3329, ζ = 17.

/// Field modulus q = 256·13 + 1.
pub(crate) const Q: u16 = 3329;

/// Polynomial degree n = 256.
pub(crate) const N: usize = 256;

/// Coefficients of a polynomial in R_q, always kept in `[0, q)`.
pub(crate) type Poly = [u16; N];

const ZETA: u16 = 17;
/// ⌊2^24 / q⌋, used by Barrett reduction.
const BARRETT_MULTIPLIER: u32 = 5039;
const BARRETT_SHIFT: u32 = 24;
/// 128^{-1} mod q, applied at the end of the inverse NTT.
const INVERSE_DEGREE: u16 = Q - 2 * 13; // 3303

const fn bitrev7(mut x: u16) -> u16 {
    let mut r = 0u16;
    let mut i = 0;
    while i < 7 {
        r = (r << 1) | (x & 1);
        x >>= 1;
        i += 1;
    }
    r
}

const fn mul_mod(a: u16, b: u16) -> u16 {
    ((a as u32 * b as u32) % Q as u32) as u16
}

const fn pow_mod(mut base: u16, mut exp: u16) -> u16 {
    let mut r = 1u16;
    while exp > 0 {
        if exp & 1 == 1 {
            r = mul_mod(r, base);
        }
        base = mul_mod(base, base);
        exp >>= 1;
    }
    r
}

/// `ZETAS[k] = ζ^{brv₇(k)} mod q` (FIPS 203 App. A). Index 0 is unused.
const ZETAS: [u16; 128] = {
    let mut z = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        z[i] = pow_mod(ZETA, bitrev7(i as u16));
        i += 1;
    }
    z
};

/// Pointwise-multiply twiddles `γ_i = ζ^{2·brv₇(i)+1} mod q`.
const GAMMAS: [u16; 128] = {
    let mut g = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        g[i] = pow_mod(ZETA, 2 * bitrev7(i as u16) + 1);
        i += 1;
    }
    g
};

/// Inverse-NTT twiddles in consumption order: inverses of `ZETAS[64..128]`,
/// then `ZETAS[32..64]`, …, then `ZETAS[1..2]`.
const INV_ZETAS: [u16; 127] = {
    let mut out = [0u16; 127];
    let mut n = 0;
    let mut start = 64usize;
    let mut count = 64usize;
    while count > 0 {
        let mut k = start;
        while k < start + count {
            out[n] = pow_mod(ZETAS[k], Q - 2);
            n += 1;
            k += 1;
        }
        start /= 2;
        count /= 2;
    }
    out
};

/// Reduce `0 ≤ x < 2q` into `[0, q)` without branching.
#[inline(always)]
pub(crate) fn reduce_once(x: u16) -> u16 {
    let subtracted = x.wrapping_sub(Q);
    // 0xffff when `x` underflowed (i.e. x < q), else 0.
    let mask = 0u16.wrapping_sub(subtracted >> 15);
    (mask & x) | (!mask & subtracted)
}

/// Barrett reduction of `x < q + 2q²` into `[0, q)`.
#[inline(always)]
pub(crate) fn reduce(x: u32) -> u16 {
    let quotient = ((x as u64 * BARRETT_MULTIPLIER as u64) >> BARRETT_SHIFT) as u32;
    reduce_once((x.wrapping_sub(quotient * Q as u32)) as u16)
}

/// `(a + b) mod q` for `a, b < q`.
#[inline(always)]
pub(crate) fn add(a: u16, b: u16) -> u16 {
    reduce_once(a + b)
}

/// `(a - b) mod q` for `a, b < q`.
#[inline(always)]
pub(crate) fn sub(a: u16, b: u16) -> u16 {
    reduce_once(a + Q - b)
}

/// In-place forward NTT (FIPS 203 Algorithm 9).
pub(crate) fn ntt(f: &mut Poly) {
    let mut k = 1usize;
    let mut len = N / 2;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k] as u32;
            k += 1;
            for j in start..start + len {
                let t = reduce(zeta * f[j + len] as u32);
                f[j + len] = sub(f[j], t);
                f[j] = add(f[j], t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// In-place inverse NTT (Gentleman–Sande form, FIPS 203 Algorithm 10).
pub(crate) fn intt(f: &mut Poly) {
    let mut ri = 0usize;
    let mut offset = 2usize;
    while offset < N {
        let mut start = 0usize;
        while start < N {
            let zeta = INV_ZETAS[ri] as u32;
            ri += 1;
            for j in start..start + offset {
                let even = f[j];
                let odd = f[j + offset];
                f[j + offset] = reduce(zeta * sub(even, odd) as u32);
                f[j] = add(even, odd);
            }
            start += 2 * offset;
        }
        offset *= 2;
    }
    for c in f.iter_mut() {
        *c = reduce(INVERSE_DEGREE as u32 * *c as u32);
    }
}

/// Multiply two NTT-domain polynomials coefficient-wise (FIPS 203 BaseCaseMultiply).
pub(crate) fn mul_pointwise(a: &Poly, b: &Poly) -> Poly {
    let mut c = [0u16; N];
    for i in 0..N / 2 {
        let a0 = a[2 * i] as u32;
        let a1 = a[2 * i + 1] as u32;
        let b0 = b[2 * i] as u32;
        let b1 = b[2 * i + 1] as u32;
        let g = GAMMAS[i] as u32;
        c[2 * i] = reduce(a0 * b0 + reduce(a1 * b1) as u32 * g);
        c[2 * i + 1] = reduce(a0 * b1 + a1 * b0);
    }
    c
}

/// `dst += a` coefficient-wise, reducing mod q.
pub(crate) fn add_assign(dst: &mut Poly, a: &Poly) {
    for i in 0..N {
        dst[i] = add(dst[i], a[i]);
    }
}

/// `dst -= a` coefficient-wise, reducing mod q.
pub(crate) fn sub_assign(dst: &mut Poly, a: &Poly) {
    for i in 0..N {
        dst[i] = sub(dst[i], a[i]);
    }
}

/// Fresh zero polynomial.
pub(crate) fn zero() -> Poly {
    [0u16; N]
}
