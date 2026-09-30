//! Twisted Edwards group arithmetic for edwards25519 in extended
//! coordinates (X, Y, Z, T), ported from the ref10-style operations in
//! OpenSSL `crypto/ec/curve25519.c` (`ge_add`, `ge_p2_dbl`,
//! `ge_p3_tobytes`, `ge_frombytes_vartime`).

use super::fe;
use super::fe::Fe;
use alloc::boxed::Box;

/// d = -121665/121666 as 51-bit limbs.
pub const D: Fe = [
    0x34dca135978a3,
    0x1a8283b156ebd,
    0x5e7a26001c029,
    0x739c663a03cbb,
    0x52036cee2b6ff,
];

/// sqrt(-1) = 2^((p-1)/4) as 51-bit limbs.
pub const SQRT_M1: Fe = [
    0x61b274a0ea0b0,
    0xd5a5fc8f189d,
    0x7ef5e9cbd0c60,
    0x78595a6804c9e,
    0x2b8324804fc1d,
];

/// The base point: y = 4/5 with x positive (little-endian encoding
/// `0x5866..66e7`).
pub const BASE_COMPRESSED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Extended point (X : Y : Z : T) with x = X/Z, y = Y/Z, T = XY/Z.
#[derive(Clone, Copy)]
pub struct P3 {
    pub x: Fe,
    pub y: Fe,
    pub z: Fe,
    pub t: Fe,
}

impl P3 {
    pub const fn identity() -> Self {
        P3 {
            x: fe::ZERO,
            y: fe::ONE,
            z: fe::ONE,
            t: fe::ZERO,
        }
    }

    /// Projective identity check (X == 0 and Y == Z), used by tests.
    #[cfg(test)]
    pub fn is_identity(&self) -> bool {
        fe::is_nonzero(&self.x) == 0 && fe::to_bytes(&self.y) == fe::to_bytes(&self.z)
    }
}

/// r = p + q, following `ge_add` with the P1P1 result folded into P3.
pub fn add(p: &P3, q: &P3) -> P3 {
    let ypx = fe::add(&p.y, &p.x);
    let ymx = fe::sub(&p.y, &p.x);
    let qypx = fe::add(&q.y, &q.x);
    let qymx = fe::sub(&q.y, &q.x);

    let r_z = fe::mul(&ypx, &qypx);
    let r_y = fe::mul(&ymx, &qymx);
    let d2 = fe::add(&D, &D);
    let r_t = fe::mul(&fe::mul(&d2, &q.t), &p.t);
    let r_x = fe::mul(&p.z, &q.z);

    let t0 = fe::add(&r_x, &r_x);
    let x = fe::sub(&r_z, &r_y);
    let y = fe::add(&r_z, &r_y);
    let z = fe::add(&t0, &r_t);
    let t = fe::sub(&t0, &r_t);

    p1p1_to_p3(&x, &y, &z, &t)
}

/// P1P1 -> P3 conversion (ref10 `ge_p1p1_to_p3`).
fn p1p1_to_p3(x: &Fe, y: &Fe, z: &Fe, t: &Fe) -> P3 {
    P3 {
        x: fe::mul(x, t),
        y: fe::mul(y, z),
        z: fe::mul(z, t),
        t: fe::mul(x, y),
    }
}

/// r = 2 * p via `ge_p3_dbl`/`ge_p2_dbl`.
pub fn dbl(p: &P3) -> P3 {
    let a = fe::sq(&p.x);
    let b = fe::sq(&p.y);
    let c = fe::add(&fe::sq(&p.z), &fe::sq(&p.z)); // fe_sq2
    let t0 = fe::sq(&fe::add(&p.x, &p.y));

    let r_y = fe::add(&b, &a);
    let r_z = fe::sub(&b, &a);
    let r_x = fe::sub(&t0, &r_y);
    let r_t = fe::sub(&c, &r_z);

    p1p1_to_p3(&r_x, &r_y, &r_z, &r_t)
}

/// Encode the point: `y || sign(x) << 7`.
pub fn to_bytes(p: &P3) -> [u8; 32] {
    let recip = fe::invert(&p.z);
    let x = fe::mul(&p.x, &recip);
    let y = fe::mul(&p.y, &recip);
    let mut s = fe::to_bytes(&y);
    s[31] ^= fe::is_negative(&x) << 7;
    s
}

/// Decode a compressed point (variable time; public input only), mirroring
/// `ge_frombytes_vartime`. Returns `None` for non-decodable inputs.
pub fn from_bytes(s: &[u8; 32]) -> Option<P3> {
    let y = fe::from_bytes(s);
    let z = fe::ONE;

    let mut u = fe::sq(&y); // y^2
    let v = fe::mul(&u, &D); // dy^2
    u = fe::sub(&u, &z); // u = y^2 - 1
    let v = fe::add(&v, &z); // v = dy^2 + 1

    let w = fe::mul(&u, &v);
    let mut x = fe::pow22523(&w); // w^((p-5)/8)
    x = fe::mul(&x, &u);

    let mut vxx = fe::sq(&x);
    vxx = fe::mul(&vxx, &v);
    let check = fe::sub(&vxx, &u);
    if fe::is_nonzero(&check) != 0 {
        let check = fe::add(&vxx, &u);
        if fe::is_nonzero(&check) != 0 {
            return None;
        }
        x = fe::mul(&x, &SQRT_M1);
    }

    if fe::is_negative(&x) != (s[31] >> 7) {
        x = fe::neg(&x);
    }

    let t = fe::mul(&x, &y);
    Some(P3 { x, y, z, t })
}

/// Branch-free selection from an 8-entry table.
fn ct_select_table(table: &[P3; 16], index: u8) -> P3 {
    let mut out = [fe::ZERO; 4];
    let fields = [&table[0].x, &table[0].y, &table[0].z, &table[0].t];
    let _ = fields;
    for (i, entry) in table.iter().enumerate() {
        // mask = all ones iff i == index.
        let neq = ((index as i64) - (i as i64)) | ((i as i64) - (index as i64));
        let mask = ((((neq >> 63) & 1) as u64) ^ 1).wrapping_neg();
        for (k, f) in [&entry.x, &entry.y, &entry.z, &entry.t]
            .into_iter()
            .enumerate()
        {
            for j in 0..5 {
                out[k][j] |= f[j] & mask;
            }
        }
    }
    P3 {
        x: out[0],
        y: out[1],
        z: out[2],
        t: out[3],
    }
}

/// Constant-time fixed-base scalar multiplication.
///
/// The base-point table holds, for each of the 64 nibble windows of the
/// scalar (little-endian, radix 2^16), the sixteen multiples `0*B .. 15*B`
/// scaled by `2^(4 * window)`. One constant-time table selection and one
/// point addition per window replaces the 4 doublings + selection of the
/// generic ladder; the table is built once per process and shared.
pub fn scalarmult_base(scalar: &[u8; 32]) -> P3 {
    let table = base_table();
    let mut r = P3::identity();
    for w in (0..64).rev() {
        let byte = scalar[w / 2];
        let nibble = if w % 2 == 0 { byte & 0x0f } else { byte >> 4 };
        let entry = ct_select_table(&table[w], nibble);
        r = add(&r, &entry);
    }
    r
}

/// Lazily initialized fixed-base table (`64` windows of `16` points).
/// The first caller builds it; concurrent builders each leak a private copy
/// (bounded, one-time) and share the published one.
fn base_table() -> &'static [[P3; 16]; 64] {
    use core::sync::atomic::{AtomicPtr, Ordering};

    static PTR: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
    let existing = PTR.load(Ordering::Acquire) as *const [[P3; 16]; 64];
    if !existing.is_null() {
        // SAFETY: the pointer is only ever set to a leaked, never-freed table.
        return unsafe { &*existing };
    }
    let table: &'static [[P3; 16]; 64] = Box::leak(Box::new(build_base_table()));
    match PTR.compare_exchange(
        core::ptr::null_mut(),
        table as *const _ as *mut (),
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => table,
        Err(winner) => unsafe { &*winner.cast::<[[P3; 16]; 64]>() },
    }
}

/// `base_table[w][d] = d * 2^(4w) * B`, built by advancing `B` through four
/// doublings per window and chaining additions within a window.
fn build_base_table() -> [[P3; 16]; 64] {
    let base = from_bytes(&BASE_COMPRESSED).expect("base point decodes");
    let mut table = [[P3::identity(); 16]; 64];
    let mut adv = base;
    for w in 0..64 {
        if w > 0 {
            for _ in 0..4 {
                adv = dbl(&adv);
            }
        }
        table[w][0] = P3::identity();
        table[w][1] = adv;
        for d in 2..16 {
            table[w][d] = add(&table[w][d - 1], &adv);
        }
    }
    table
}

/// Constant-time scalar multiplication with 4-bit windows.
pub fn scalarmult(p: &P3, scalar: &[u8; 32]) -> P3 {
    let mut table = [P3::identity(); 16];
    table[1] = *p;
    for i in 2..16 {
        table[i] = add(&table[i - 1], p);
    }

    let mut r = P3::identity();
    for j in (0..64).rev() {
        let nibble = (scalar[j / 2] >> ((j % 2) * 4)) & 0x0f;
        for _ in 0..4 {
            r = dbl(&r);
        }
        let t = ct_select_table(&table, nibble);
        r = add(&r, &t);
    }
    r
}

#[cfg(test)]
mod ge_tests {
    use super::*;
    use crate::ed25519::sc;

    #[test]
    fn group_law_sanity() {
        let b = from_bytes(&BASE_COMPRESSED).unwrap();
        let b2 = dbl(&b);
        let b2b = add(&b, &b);
        assert_eq!(to_bytes(&b2), to_bytes(&b2b));

        let identity = P3::identity();
        assert_eq!(to_bytes(&add(&b, &identity)), to_bytes(&b));
        assert_eq!(to_bytes(&add(&identity, &b)), to_bytes(&b));
    }

    #[test]
    fn scalarmult_matches_naive() {
        let b = from_bytes(&BASE_COMPRESSED).unwrap();
        let mut scalar = [0u8; 32];
        scalar[0] = 9;
        let ladder = scalarmult_base(&scalar);
        let mut naive = P3::identity();
        for _ in 0..9 {
            naive = add(&naive, &b);
        }
        assert_eq!(to_bytes(&ladder), to_bytes(&naive));
    }

    // [L]B is the identity (L is the group order).
    #[test]
    fn order_of_base() {
        let r = scalarmult_base(&sc::L);
        assert!(r.is_identity());
    }
}
