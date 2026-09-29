//! Field arithmetic modulo `p = 2^448 - 2^224 - 1`, shared by X448 and
//! Ed448.
//!
//! Values are radix-2^56: eight 56-bit limbs in `u64`, little-endian in
//! limb order. Every public operation returns limbs masked to 56 bits
//! with the integer value fully reduced to `[0, p)`. The modulus
//! identity `2^448 = 2^224 + 1` is used to fold carries past the top
//! limb (lane 8 folds into lanes 0 and 4).

/// A field element: eight 56-bit limbs, little-endian.
pub type Fe = [u64; 8];

const MASK: u64 = (1 << 56) - 1;
const MASK128: u128 = (1 << 56) - 1;

pub const ZERO: Fe = [0, 0, 0, 0, 0, 0, 0, 0];
pub const ONE: Fe = [1, 0, 0, 0, 0, 0, 0, 0];

/// `p` in limb form (limb 4 is `2^56 - 2` because bit 224 of `p` is 0).
const P: Fe = [
    MASK,
    MASK,
    MASK,
    MASK,
    MASK - 1,
    MASK,
    MASK,
    MASK,
];

/// `p - 2 = 2^448 - 2^224 - 3` as 56 little-endian bytes, the inversion
/// exponent.
const P_MINUS_2: [u8; 56] = [
    0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// `(p + 1) / 4 = 2^446 - 2^222` as 56 little-endian bytes; raising to
/// this power produces a candidate square root (p = 3 mod 4).
const P_PLUS_1_DIV_4: [u8; 56] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
];

/// Carry-propagate and fold a wide radix-2^56 accumulator into a
/// canonical element.
///
/// `v` holds 9 lanes; lane 8 is the overflow past `2^448`. The identity
/// `2^448 = 2^224 + 1` folds lane 8 into lanes 0 and 4, and a carry
/// `c` past lane 8 scales by `2^504 = 2^56 * 2^448 = 2^280 + 2^56`,
/// i.e. lanes 5 and 1.
fn normalize9(v: &mut [u128; 9]) -> Fe {
    for _ in 0..4 {
        let mut c = 0u128;
        for lane in v.iter_mut() {
            let s = *lane + c;
            *lane = s & MASK128;
            c = s >> 56;
        }
        if c == 0 && v[8] == 0 {
            break;
        }
        let x8 = v[8];
        v[8] = 0;
        v[0] += x8;
        v[4] += x8;
        v[1] += c;
        v[5] += c;
    }

    let mut h = ZERO;
    let mut c = 0u128;
    for i in 0..8 {
        let s = v[i] + c;
        h[i] = (s & MASK128) as u64;
        c = s >> 56;
    }
    debug_assert_eq!(c, 0, "curve448: residual carry after normalize");
    debug_assert_eq!(v[8], 0, "curve448: residual lane 8 after normalize");

    // One conditional subtraction of p lands the value in [0, p):
    // the input is below 2^448 = p + 2^224 + 1 and 2^224 + 1 < p.
    reduce_once(&mut h);
    h
}

/// Conditionally subtract `p` once.
fn reduce_once(h: &mut Fe) {
    let mut t = [0i128; 8];
    let mut borrow = 0i128;
    for i in 0..8 {
        let d = h[i] as i128 - P[i] as i128 - borrow;
        if d < 0 {
            t[i] = d + (1i128 << 56);
            borrow = 1;
        } else {
            t[i] = d;
            borrow = 0;
        }
    }
    if borrow == 0 {
        for i in 0..8 {
            h[i] = t[i] as u64;
        }
    }
}

/// Load 56 little-endian bytes; non-canonical inputs are reduced mod p.
pub fn from_bytes(s: &[u8; 56]) -> Fe {
    let mut v = [0u128; 9];
    for i in 0..8 {
        let mut limb = 0u64;
        for j in 0..7 {
            limb |= (s[i * 7 + j] as u64) << (8 * j);
        }
        v[i] = limb as u128;
    }
    normalize9(&mut v)
}

/// Serialize as 56 little-endian bytes, fully reduced.
pub fn to_bytes(f: &Fe) -> [u8; 56] {
    let mut out = [0u8; 56];
    for i in 0..8 {
        for j in 0..7 {
            out[i * 7 + j] = (f[i] >> (8 * j)) as u8;
        }
    }
    out
}

pub fn add(f: &Fe, g: &Fe) -> Fe {
    let mut v = [0u128; 9];
    for i in 0..8 {
        v[i] = f[i] as u128 + g[i] as u128;
    }
    normalize9(&mut v)
}

pub fn sub(f: &Fe, g: &Fe) -> Fe {
    // f + 2p - g is limb-wise non-negative when limbs are below 2^56,
    // and is congruent to f - g mod p.
    let mut v = [0u128; 9];
    for i in 0..8 {
        v[i] = f[i] as u128 + 2 * (P[i] as u128) - g[i] as u128;
    }
    normalize9(&mut v)
}

pub fn neg(f: &Fe) -> Fe {
    sub(&ZERO, f)
}

pub fn mul(f: &Fe, g: &Fe) -> Fe {
    let mut t = [0u128; 16];
    for i in 0..8 {
        for j in 0..8 {
            t[i + j] += (f[i] as u128) * (g[j] as u128);
        }
    }
    // value = LO + HI * 2^448 ≡ LO + HI + HI * 2^224 (mod p).
    // HI * 2^224 shifts the high half up four lanes, so the first fold
    // needs 12 lanes (t[12..16] land in lanes 8..12).
    let mut v = [0u128; 12];
    for j in 0..8 {
        v[j] = t[j] + t[j + 8] + if j >= 4 { t[j + 4] } else { 0 };
    }
    v[8..12].copy_from_slice(&t[12..16]);
    // Fold lanes 8..12 with 2^448 = 2^224 + 1 (into lanes j-8 and j-4).
    for j in 8..12 {
        let x = v[j];
        v[j] = 0;
        v[j - 8] += x;
        v[j - 4] += x;
    }
    let mut w = [0u128; 9];
    w[..8].copy_from_slice(&v[..8]);
    normalize9(&mut w)
}

pub fn sq(f: &Fe) -> Fe {
    mul(f, f)
}

/// `h = f * k` for a small scalar `k` (used for a24 = 39081).
pub fn mul_small(f: &Fe, k: u32) -> Fe {
    let mut v = [0u128; 9];
    for i in 0..8 {
        v[i] = f[i] as u128 * k as u128;
    }
    normalize9(&mut v)
}

/// Square-and-multiply `z^e` for a little-endian exponent `e`.
fn pow_le(z: &Fe, e: &[u8]) -> Fe {
    let mut acc = ONE;
    for byte in e.iter().rev() {
        for bit in (0..8).rev() {
            acc = sq(&acc);
            if (byte >> bit) & 1 == 1 {
                acc = mul(&acc, z);
            }
        }
    }
    acc
}

/// Reciprocal `z^(p - 2)`; `invert(0) = 0`.
pub fn invert(z: &Fe) -> Fe {
    pow_le(z, &P_MINUS_2)
}

/// Candidate square root `z^((p + 1) / 4)`. When `z` is a quadratic
/// residue the square of the result is `z`; otherwise no root exists.
pub fn pow_p_plus_1_div_4(z: &Fe) -> Fe {
    pow_le(z, &P_PLUS_1_DIV_4)
}

/// 1 if the canonical encoding has bit 0 set (the "sign" bit).
pub fn is_negative(f: &Fe) -> u8 {
    to_bytes(f)[0] & 1
}

/// 1 if the element is not zero.
pub fn is_nonzero(f: &Fe) -> u8 {
    let t = to_bytes(f);
    let mut acc = 0u8;
    for b in t {
        acc |= b;
    }
    (acc != 0) as u8
}

/// Constant-time swap of two field elements when `bit` is 0 or 1.
pub fn cswap(a: &mut Fe, b: &mut Fe, bit: u64) {
    let mask = 0u64.wrapping_sub(bit);
    for i in 0..8 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe_eq(a: &Fe, b: &Fe) -> bool {
        to_bytes(a) == to_bytes(b)
    }

    #[test]
    fn one_is_one() {
        let mut one_bytes = [0u8; 56];
        one_bytes[0] = 1;
        assert_eq!(to_bytes(&ONE), one_bytes);
        assert_eq!(from_bytes(&one_bytes), ONE);
    }

    /// 2^448 - 1 (all-ones input) reduces to 2^224 (mod p).
    #[test]
    fn top_value_reduces() {
        let f = from_bytes(&[0xffu8; 56]);
        let mut expected = [0u8; 56];
        expected[28] = 1; // 2^224
        assert_eq!(to_bytes(&f), expected);
    }

    /// 2^448 - 2^224 - 1 = p reduces to 0.
    #[test]
    fn p_reduces_to_zero() {
        let mut p_bytes = [0u8; 56];
        // p = 2^448 - 2^224 - 1: bits 0..223 set, bit 224 clear, bits 225..447 set.
        for b in p_bytes.iter_mut() {
            *b = 0xff;
        }
        p_bytes[28] = 0xfe;
        assert_eq!(to_bytes(&from_bytes(&p_bytes)), [0u8; 56]);
    }

    #[test]
    fn invert_roundtrip() {
        let mut z = [0u64; 8];
        z[0] = 12345;
        z[3] = 6789;
        z[7] = 0x1234;
        let zi = invert(&z);
        assert!(fe_eq(&mul(&z, &zi), &ONE), "z * z^-1 == 1");

        let two = [2, 0, 0, 0, 0, 0, 0, 0];
        assert!(fe_eq(&mul(&two, &invert(&two)), &ONE));
    }

    #[test]
    fn mul_small_matches_mul() {
        let f = from_bytes(&[
            0x02, 0x11, 0x28, 0x7c, 0xfe, 0x42, 0x30, 0x1b, 0xfe, 0x3c, 0x0a, 0xc2, 0x4c, 0x8e,
            0x47, 0x7e, 0x51, 0xd1, 0x9b, 0xf9, 0x2b, 0x9c, 0x51, 0x17, 0x09, 0x53, 0x2e, 0x40,
            0x1b, 0xd5, 0x8a, 0x0f, 0x33, 0x21, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0,
        ]);
        let k39081 = [39081, 0, 0, 0, 0, 0, 0, 0];
        assert!(fe_eq(&mul_small(&f, 39081), &mul(&f, &k39081)));
    }

    #[test]
    fn distributivity() {
        let x = from_bytes(&[
            0x02, 0x11, 0x28, 0x7c, 0xfe, 0x42, 0x30, 0x1b, 0xfe, 0x3c, 0x0a, 0xc2, 0x4c, 0x8e,
            0x47, 0x7e, 0x51, 0xd1, 0x9b, 0xf9, 0x2b, 0x9c, 0x51, 0x17, 0x09, 0x53, 0x2e, 0x40,
            0x1b, 0xd5, 0x8a, 0x0f, 0x33, 0x21, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0,
        ]);
        let y = from_bytes(&[
            0xc9, 0x71, 0xc9, 0x69, 0xa4, 0x32, 0x2c, 0x10, 0xa3, 0x31, 0x13, 0x77, 0x0e, 0xd1,
            0x63, 0xba, 0x1c, 0x51, 0x9a, 0x63, 0xd5, 0xc9, 0xd9, 0x0c, 0x93, 0x91, 0x2c, 0xb1,
            0x02, 0x9e, 0x63, 0x15, 0x44, 0x33, 0x22, 0x11, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33,
            0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x01,
        ]);
        let lhs = sq(&add(&x, &y));
        let mut rhs = add(&sq(&x), &sq(&y));
        let two = [2, 0, 0, 0, 0, 0, 0, 0];
        rhs = add(&rhs, &mul(&mul(&x, &y), &two));
        assert!(fe_eq(&lhs, &rhs));
    }

    #[test]
    fn sqrt_of_square() {
        let x = from_bytes(&[
            0x42, 0x11, 0x28, 0x7c, 0xfe, 0x42, 0x30, 0x1b, 0xfe, 0x3c, 0x0a, 0xc2, 0x4c, 0x8e,
            0x47, 0x7e, 0x51, 0xd1, 0x9b, 0xf9, 0x2b, 0x9c, 0x51, 0x17, 0x09, 0x53, 0x2e, 0x40,
            0x1b, 0xd5, 0x8a, 0x0f, 0x33, 0x21, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0,
        ]);
        let sqx = sq(&x);
        let root = pow_p_plus_1_div_4(&sqx);
        // root^2 == sqx or (root * sqrt(-1))^2 == sqx; here x^2 is a
        // residue so at least one of ±root squares to sqx.
        let r2 = sq(&root);
        assert!(
            fe_eq(&r2, &sqx) || fe_eq(&r2, &neg(&sqx)),
            "candidate root squares to ±z"
        );
    }
}
