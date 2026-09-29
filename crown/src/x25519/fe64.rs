#![allow(dead_code, unused_imports)]
//! Curve25519 field arithmetic in radix-2^64 (four 64-bit limbs).
//!
//! Values are little-endian limb vectors, partially reduced mod
//! `2^256 - 38` (= 2p). Only [`to_bytes`] fully reduces to `[0, p)`.
//! When the `asm` feature is enabled the x25519-x86_64.pl helpers in
//! [`crate::ed25519::asm`] implement the arithmetic; otherwise these
//! portable routines match the same invariants.

pub type Fe64 = [u64; 4];

pub const ZERO: Fe64 = [0, 0, 0, 0];
#[cfg(test)]
pub const ONE: Fe64 = [1, 0, 0, 0];

/// Load a 32-byte little-endian value; the top bit is masked off, as in
/// OpenSSL's `fe64_frombytes` / X25519 point decoding.
pub fn from_bytes(s: &[u8; 32]) -> Fe64 {
    let mut h = ZERO;
    for i in 0..4 {
        h[i] = u64::from_le_bytes(s[i * 8..i * 8 + 8].try_into().unwrap());
    }
    h[3] &= 0x7fff_ffff_ffff_ffff;
    h
}

/// Fully reduce and serialize as 32 little-endian bytes.
pub fn to_bytes(h: &Fe64) -> [u8; 32] {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        crate::ed25519::asm::fe64_tobytes(h)
    }
    #[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
    to_bytes_generic(h)
}

fn to_bytes_generic(h: &Fe64) -> [u8; 32] {
    // Fold bit 255 using 2^255 ≡ 19, then conditionally subtract p.
    let mut n = *h;
    let top = n[3] >> 63;
    n[3] &= 0x7fff_ffff_ffff_ffff;
    let mut c = 19u128 * top as u128;
    for limb in n.iter_mut() {
        let s = *limb as u128 + c;
        *limb = s as u64;
        c = s >> 64;
    }
    debug_assert_eq!(c, 0);

    // t = n + 19; if t >= 2^255 then n >= p, and t - 2^255 = n - p.
    let mut t = n;
    let mut c = 19u128;
    for limb in t.iter_mut() {
        let s = *limb as u128 + c;
        *limb = s as u64;
        c = s >> 64;
    }
    if t[3] >> 63 == 1 {
        t[3] &= 0x7fff_ffff_ffff_ffff;
        n = t;
    }

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&n[i].to_le_bytes());
    }
    out
}

pub fn add(f: &Fe64, g: &Fe64) -> Fe64 {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        crate::ed25519::asm::fe64_add(f, g)
    }
    #[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
    add_generic(f, g)
}

fn add_generic(f: &Fe64, g: &Fe64) -> Fe64 {
    let mut h = ZERO;
    let mut c = 0u128;
    for i in 0..4 {
        let s = f[i] as u128 + g[i] as u128 + c;
        h[i] = s as u64;
        c = s >> 64;
    }
    // 2^256 ≡ 38 (mod 2^256-38)
    fold38(&mut h, c as u64);
    h
}

pub fn sub(f: &Fe64, g: &Fe64) -> Fe64 {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        crate::ed25519::asm::fe64_sub(f, g)
    }
    #[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
    sub_generic(f, g)
}

fn sub_generic(f: &Fe64, g: &Fe64) -> Fe64 {
    let mut h = ZERO;
    let mut borrow = 0i128;
    for i in 0..4 {
        let s = f[i] as i128 - g[i] as i128 - borrow;
        if s < 0 {
            h[i] = (s + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            h[i] = s as u64;
            borrow = 0;
        }
    }
    // borrowed 2^256 ≡ 38, so subtract 38 to stay congruent.
    if borrow == 1 {
        fold38_sub(&mut h, 38);
    }
    h
}

pub fn mul(f: &Fe64, g: &Fe64) -> Fe64 {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        crate::ed25519::asm::fe64_mul(f, g)
    }
    #[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
    mul_generic(f, g)
}

fn mul_generic(f: &Fe64, g: &Fe64) -> Fe64 {
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let idx = i + j;
            let s = t[idx] as u128 + (f[i] as u128) * (g[j] as u128) + carry;
            t[idx] = s as u64;
            carry = s >> 64;
        }
        t[i + 4] = carry as u64;
    }
    reduce_wide(&t)
}

pub fn sq(f: &Fe64) -> Fe64 {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        crate::ed25519::asm::fe64_sqr(f)
    }
    #[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
    mul_generic(f, f)
}

/// `h = f * 121666` (the Curve25519 a24+1 used by the Montgomery ladder).
pub fn mul121666(f: &Fe64) -> Fe64 {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        crate::ed25519::asm::fe64_mul121666(f)
    }
    #[cfg(any(not(feature = "asm"), not(target_arch = "x86_64")))]
    mul121666_generic(f)
}

fn mul121666_generic(f: &Fe64) -> Fe64 {
    let mut h = ZERO;
    let mut carry = 0u128;
    for i in 0..4 {
        let s = f[i] as u128 * 121666 + carry;
        h[i] = s as u64;
        carry = s >> 64;
    }
    fold38(&mut h, carry as u64);
    h
}

/// Constant-time swap of two field elements when `b` is 0 or 1.
pub fn cswap(a: &mut Fe64, b: &mut Fe64, bit: u64) {
    let mask = 0u64.wrapping_sub(bit);
    for i in 0..4 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// Reciprocal `z^(p-2)` via the ref10 addition chain.
pub fn invert(z: &Fe64) -> Fe64 {
    let sq = |x: &Fe64| sq(x);
    let mut t0 = sq(z);
    let mut t1 = sq(&t0);
    t1 = sq(&t1);
    t1 = mul(z, &t1);
    t0 = mul(&t0, &t1);

    let mut t2 = sq(&t0);
    t1 = mul(&t1, &t2);

    t2 = sq(&t1);
    for _ in 1..5 {
        t2 = sq(&t2);
    }
    t1 = mul(&t2, &t1);

    t2 = sq(&t1);
    for _ in 1..10 {
        t2 = sq(&t2);
    }
    t2 = mul(&t2, &t1);

    let mut t3 = sq(&t2);
    for _ in 1..20 {
        t3 = sq(&t3);
    }
    t2 = mul(&t3, &t2);

    for _ in 0..10 {
        t2 = sq(&t2);
    }
    t1 = mul(&t2, &t1);

    t2 = sq(&t1);
    for _ in 1..50 {
        t2 = sq(&t2);
    }
    t2 = mul(&t2, &t1);

    t3 = sq(&t2);
    for _ in 1..100 {
        t3 = sq(&t3);
    }
    t2 = mul(&t3, &t2);

    t2 = sq(&t2);
    for _ in 1..50 {
        t2 = sq(&t2);
    }
    t1 = mul(&t2, &t1);

    t1 = sq(&t1);
    for _ in 1..5 {
        t1 = sq(&t1);
    }
    mul(&t1, &t0)
}

fn fold38(h: &mut Fe64, mut extra: u64) {
    // h += 38 * extra, twice, to land mod 2^256-38.
    for _ in 0..3 {
        if extra == 0 {
            break;
        }
        let mut c = 38u128 * extra as u128;
        for limb in h.iter_mut() {
            let s = *limb as u128 + c;
            *limb = s as u64;
            c = s >> 64;
        }
        extra = c as u64;
    }
}

fn fold38_sub(h: &mut Fe64, mut extra: u64) {
    for _ in 0..3 {
        if extra == 0 {
            break;
        }
        let mut borrow = extra as u128;
        for limb in h.iter_mut() {
            let s = *limb as i128 - borrow as i128;
            if s < 0 {
                *limb = (s + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                *limb = s as u64;
                borrow = 0;
            }
        }
        extra = borrow as u64;
    }
}

fn reduce_wide(t: &[u64; 8]) -> Fe64 {
    // value = t[0..4] + t[4..8] * 2^256 ≡ t[0..4] + t[4..8] * 38
    let mut h = ZERO;
    let mut c = 0u128;
    for i in 0..4 {
        let s = t[i] as u128 + 38u128 * (t[i + 4] as u128) + c;
        h[i] = s as u64;
        c = s >> 64;
    }
    fold38(&mut h, c as u64);
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Portable routines must agree with the x25519-x86_64.pl helpers.
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    #[test]
    fn generic_matches_asm() {
        use crate::ed25519::asm;
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for n in 0..16 {
            let mut a = [0u64; 4];
            let mut b = [0u64; 4];
            for i in 0..4 {
                a[i] = next();
                b[i] = next();
            }
            a[3] &= 0x7fff_ffff_ffff_ffff;
            b[3] &= 0x7fff_ffff_ffff_ffff;

            let got = to_bytes_generic(&add_generic(&a, &b));
            let want = asm::fe64_tobytes(&asm::fe64_add(&a, &b));
            assert_eq!(got, want, "add n={n}");

            let got = to_bytes_generic(&sub_generic(&a, &b));
            let want = asm::fe64_tobytes(&asm::fe64_sub(&a, &b));
            assert_eq!(got, want, "sub n={n}");

            let got = to_bytes_generic(&mul_generic(&a, &b));
            let want = asm::fe64_tobytes(&asm::fe64_mul(&a, &b));
            assert_eq!(got, want, "mul n={n}");

            let got = to_bytes_generic(&mul121666_generic(&a));
            let want = asm::fe64_tobytes(&asm::fe64_mul121666(&a));
            assert_eq!(got, want, "mul121666 n={n}");
        }
    }

    #[test]
    fn invert_roundtrip() {
        let mut z = [0u64; 4];
        z[0] = 12345;
        z[1] = 6789;
        z[3] = 0x1234;
        let zi = invert(&z);
        let prod = mul(&z, &zi);
        assert_eq!(to_bytes(&prod), to_bytes(&ONE), "z * z^-1 == 1");
    }
}
