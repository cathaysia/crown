//! Field arithmetic modulo `p = 2^255 - 19` with five 51-bit limbs.
//!
//! Portable radix-2^51 representation (u64 limbs, u128 intermediates),
//! equivalent to OpenSSL's ref10-style field arithmetic in
//! `crypto/ec/curve25519.c`. Limb bounds are kept below 2^54 so that the
//! 9-term product chain in [`mul`] never overflows u128.

/// A field element: five 51-bit limbs, little-endian in limb order.
pub type Fe = [u64; 5];

const MASK: u64 = (1 << 51) - 1;

pub const ZERO: Fe = [0, 0, 0, 0, 0];
pub const ONE: Fe = [1, 0, 0, 0, 0];

/// p in limb form, used as the offset for subtraction (a single p is
/// enough to keep the difference non-negative, and 2p would not fit in
/// five 51-bit limbs).
const P: Fe = [
    (1 << 51) - 19,
    (1 << 51) - 1,
    (1 << 51) - 1,
    (1 << 51) - 1,
    (1 << 51) - 1,
];

pub fn add(f: &Fe, g: &Fe) -> Fe {
    let mut h = ZERO;
    for i in 0..5 {
        h[i] = f[i] + g[i];
    }
    h
}

pub fn sub(f: &Fe, g: &Fe) -> Fe {
    let mut t = [0i64; 5];
    for i in 0..5 {
        t[i] = f[i] as i64 + P[i] as i64 - g[i] as i64;
    }
    propagate(&mut t);
    let mut h = ZERO;
    for i in 0..5 {
        h[i] = t[i] as u64;
    }
    h
}

pub fn neg(f: &Fe) -> Fe {
    sub(&ZERO, f)
}

fn propagate(t: &mut [i64; 5]) {
    for i in 0..4 {
        let c = t[i] >> 51;
        t[i] &= MASK as i64;
        t[i + 1] += c;
    }
    // Fold the top carry back into the low limb.
    let c = t[4] >> 51;
    t[4] &= MASK as i64;
    t[0] += c * 19;
    let c = t[0] >> 51;
    t[0] &= MASK as i64;
    t[1] += c;
}

/// h = f * g.
pub fn mul(f: &Fe, g: &Fe) -> Fe {
    let mut r = [0u128; 5];

    r[0] = (f[0] as u128) * (g[0] as u128)
        + 19 * ((f[1] as u128) * (g[4] as u128)
            + (f[2] as u128) * (g[3] as u128)
            + (f[3] as u128) * (g[2] as u128)
            + (f[4] as u128) * (g[1] as u128));
    r[1] = (f[0] as u128) * (g[1] as u128)
        + (f[1] as u128) * (g[0] as u128)
        + 19 * ((f[2] as u128) * (g[4] as u128)
            + (f[3] as u128) * (g[3] as u128)
            + (f[4] as u128) * (g[2] as u128));
    r[2] = (f[0] as u128) * (g[2] as u128)
        + (f[1] as u128) * (g[1] as u128)
        + (f[2] as u128) * (g[0] as u128)
        + 19 * ((f[3] as u128) * (g[4] as u128) + (f[4] as u128) * (g[3] as u128));
    r[3] = (f[0] as u128) * (g[3] as u128)
        + (f[1] as u128) * (g[2] as u128)
        + (f[2] as u128) * (g[1] as u128)
        + (f[3] as u128) * (g[0] as u128)
        + 19 * ((f[4] as u128) * (g[4] as u128));
    r[4] = (f[0] as u128) * (g[4] as u128)
        + (f[1] as u128) * (g[3] as u128)
        + (f[2] as u128) * (g[2] as u128)
        + (f[3] as u128) * (g[1] as u128)
        + (f[4] as u128) * (g[0] as u128);

    carry_u128(&mut r);

    let mut h = ZERO;
    for i in 0..5 {
        h[i] = r[i] as u64;
    }
    h
}

pub fn sq(f: &Fe) -> Fe {
    mul(f, f)
}

/// Full carry chain including the 2^255 -> 19 fold and one extra
/// propagation round, leaving all limbs in `[0, 2^51)`.
pub fn carry(h: &mut Fe) {
    let mut c: u64;
    for i in 0..4 {
        c = h[i] >> 51;
        h[i] &= MASK;
        h[i + 1] += c;
    }
    c = h[4] >> 51;
    h[4] &= MASK;
    h[0] += c * 19;
    c = h[0] >> 51;
    h[0] &= MASK;
    h[1] += c;
}

fn carry_u128(r: &mut [u128; 5]) {
    let mut c: u128;
    for i in 0..4 {
        c = r[i] >> 51;
        r[i] &= MASK as u128;
        r[i + 1] += c;
    }
    c = r[4] >> 51;
    r[4] &= MASK as u128;
    r[0] += c * 19;
    c = r[0] >> 51;
    r[0] &= MASK as u128;
    r[1] += c;
}

/// Conditionally subtract p once (all limbs below 2^51). The trick: add 19
/// and drop the carry out of bit 255, which subtracts 2^255 = p - 19.
fn reduce_once(h: &mut Fe) {
    let mut q = (h[0] + 19) >> 51;
    q = (h[1] + q) >> 51;
    q = (h[2] + q) >> 51;
    q = (h[3] + q) >> 51;
    q = (h[4] + q) >> 51;

    h[0] += 19 * q;
    let mut c = h[0] >> 51;
    h[0] &= MASK;
    for i in 1..5 {
        h[i] += c;
        c = h[i] >> 51;
        h[i] &= MASK;
    }
    // The final carry equals q and represents the subtracted 2^255.
}

/// Load a 32-byte little-endian integer (top bit ignored) fully reduced.
pub fn from_bytes(s: &[u8; 32]) -> Fe {
    let l0 = u64::from_le_bytes(s[0..8].try_into().unwrap());
    let l1 = u64::from_le_bytes(s[8..16].try_into().unwrap());
    let l2 = u64::from_le_bytes(s[16..24].try_into().unwrap());
    let l3 = u64::from_le_bytes(s[24..32].try_into().unwrap());

    let mut h = [
        l0 & MASK,
        (l0 >> 51) | ((l1 << 13) & MASK),
        (l1 >> 38) | ((l2 << 26) & MASK),
        (l2 >> 25) | ((l3 << 39) & MASK),
        (l3 >> 12) & MASK,
    ];
    carry(&mut h);
    reduce_once(&mut h);
    h
}

/// Serialize to 32 little-endian bytes, fully reduced and canonical.
pub fn to_bytes(h: &Fe) -> [u8; 32] {
    let mut t = *h;
    carry(&mut t);
    reduce_once(&mut t);

    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&(t[0] | (t[1] << 51)).to_le_bytes());
    out[8..16].copy_from_slice(&((t[1] >> 13) | (t[2] << 38)).to_le_bytes());
    out[16..24].copy_from_slice(&((t[2] >> 26) | (t[3] << 25)).to_le_bytes());
    out[24..32].copy_from_slice(&((t[3] >> 39) | (t[4] << 12)).to_le_bytes());
    out
}

/// Reciprocal via the z^(p-2) addition chain (ref10 `fe_invert`).
pub fn invert(z: &Fe) -> Fe {
    // out = z^(2^255 - 21) with the exponent as (2^5) * (2^250 - 1) + 11.
    let mut t0 = sq(z); // z^2
    let mut t1 = sq(&t0);
    t1 = sq(&t1); // z^8
    t1 = mul(z, &t1); // z^9
    t0 = mul(&t0, &t1); // z^11 (stashed for the end)

    let mut t2 = sq(&t0); // z^22
    t1 = mul(&t1, &t2); // z^(2^5 - 1)

    t2 = sq(&t1);
    for _ in 1..5 {
        t2 = sq(&t2);
    }
    t1 = mul(&t2, &t1); // z^(2^10 - 1)

    t2 = sq(&t1);
    for _ in 1..10 {
        t2 = sq(&t2);
    }
    t2 = mul(&t2, &t1); // z^(2^20 - 1)

    let mut t3 = sq(&t2);
    for _ in 1..20 {
        t3 = sq(&t3);
    }
    t2 = mul(&t3, &t2); // z^(2^40 - 1)

    for _ in 0..10 {
        t2 = sq(&t2);
    }
    t1 = mul(&t2, &t1); // z^(2^50 - 1)

    t2 = sq(&t1);
    for _ in 1..50 {
        t2 = sq(&t2);
    }
    t2 = mul(&t2, &t1); // z^(2^100 - 1)

    t3 = sq(&t2);
    for _ in 1..100 {
        t3 = sq(&t3);
    }
    t2 = mul(&t3, &t2); // z^(2^200 - 1)

    t2 = sq(&t2);
    for _ in 1..50 {
        t2 = sq(&t2);
    }
    t1 = mul(&t2, &t1); // z^(2^250 - 1)

    t1 = sq(&t1);
    for _ in 1..5 {
        t1 = sq(&t1);
    }
    mul(&t1, &t0)
}

/// z^((p-5)/8) via the ref10 `fe_pow22523` chain.
pub fn pow22523(z: &Fe) -> Fe {
    let mut t0 = sq(z); // z^2
    let mut t1 = sq(&t0);
    t1 = sq(&t1); // z^8
    t1 = mul(z, &t1); // z^9
    t0 = mul(&t0, &t1); // z^11

    t0 = sq(&t0); // z^22
    t0 = mul(&t1, &t0); // z^31

    t1 = sq(&t0);
    for _ in 1..5 {
        t1 = sq(&t1);
    }
    t0 = mul(&t1, &t0); // z^(2^10 - 1)

    t1 = sq(&t0);
    for _ in 1..10 {
        t1 = sq(&t1);
    }
    t1 = mul(&t1, &t0); // z^(2^20 - 1)

    let mut t2 = sq(&t1);
    for _ in 1..20 {
        t2 = sq(&t2);
    }
    t1 = mul(&t2, &t1); // z^(2^40 - 1)

    t1 = sq(&t1);
    for _ in 1..10 {
        t1 = sq(&t1);
    }
    t0 = mul(&t1, &t0); // z^(2^50 - 1)

    t1 = sq(&t0);
    for _ in 1..50 {
        t1 = sq(&t1);
    }
    t1 = mul(&t1, &t0); // z^(2^100 - 1)

    t2 = sq(&t1);
    for _ in 1..100 {
        t2 = sq(&t2);
    }
    t1 = mul(&t2, &t1); // z^(2^200 - 1)

    t1 = sq(&t1);
    for _ in 1..50 {
        t1 = sq(&t1);
    }
    t0 = mul(&t1, &t0); // z^(2^250 - 1)

    t0 = sq(&t0);
    t0 = sq(&t0); // z^(2^252 - 4)

    mul(&t0, z) // z^(2^252 - 3) = z^((p-5)/8)
}

/// 1 if the canonical encoding has bit 0 set.
pub fn is_negative(f: &Fe) -> u8 {
    to_bytes(f)[0] & 1
}

/// 1 if the element is not zero (canonicalized first).
pub fn is_nonzero(f: &Fe) -> u8 {
    let t = to_bytes(f);
    let mut acc = 0u8;
    for b in t {
        acc |= b;
    }
    (acc != 0) as u8
}

#[cfg(test)]
mod fe_tests {
    use super::*;

    // 2^255 - 1 == 18 (mod p): the all-ones top-bit-cleared encoding.
    #[test]
    fn top_value_reduces() {
        let mut bytes = [0xffu8; 32];
        bytes[31] = 0x7f;
        let f = from_bytes(&bytes);
        let mut expected = [0u8; 32];
        expected[0] = 18;
        assert_eq!(to_bytes(&f), expected);
    }

    // 2 * 2^-1 == 1.
    #[test]
    fn inverse_of_two() {
        let two = [2, 0, 0, 0, 0];
        let inv = invert(&two);
        assert_eq!(to_bytes(&mul(&two, &inv)), {
            let mut e = [0u8; 32];
            e[0] = 1;
            e
        });
    }

    // (x + y)^2 == x^2 + 2xy + y^2 on random-ish values.
    #[test]
    fn distributivity() {
        let x = from_bytes(&[
            0x02, 0x11, 0x28, 0x7c, 0xfe, 0x42, 0x30, 0x1b, 0xfe, 0x3c, 0x0a, 0xc2, 0x4c, 0x8e,
            0x47, 0x7e, 0x51, 0xd1, 0x9b, 0xf9, 0x2b, 0x9c, 0x51, 0x17, 0x09, 0x53, 0x2e, 0x40,
            0x1b, 0xd5, 0x8a, 0x0f,
        ]);
        let y = from_bytes(&[
            0xc9, 0x71, 0xc9, 0x69, 0xa4, 0x32, 0x2c, 0x10, 0xa3, 0x31, 0x13, 0x77, 0x0e, 0xd1,
            0x63, 0xba, 0x1c, 0x51, 0x9a, 0x63, 0xd5, 0xc9, 0xd9, 0x0c, 0x93, 0x91, 0x2c, 0xb1,
            0x02, 0x9e, 0x63, 0x15,
        ]);
        let xpy = add(&x, &y);
        let lhs = sq(&xpy);
        let mut rhs = add(&sq(&x), &sq(&y));
        let two_xy = mul(&mul(&x, &y), &[2, 0, 0, 0, 0]);
        rhs = add(&rhs, &two_xy);
        assert_eq!(to_bytes(&lhs), to_bytes(&rhs));
    }
}
