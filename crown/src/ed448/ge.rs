//! Edwards group arithmetic for edwards448 (RFC 7748 §4.2 / RFC 8032 §5.2).
//!
//! The curve is the *untwisted* Edwards curve `x^2 + y^2 = 1 + d x^2 y^2`
//! with `d = -39081` (a = +1). Points are kept in extended coordinates
//! `(X : Y : Z : T)` with `x = X/Z`, `y = Y/Z`, `T = XY/Z`, matching the
//! shape of [`crate::ed25519::ge`]. Addition and doubling follow the
//! complete formulas in RFC 8032 §5.2.4.

use crate::curve448::fe;
use crate::curve448::fe::Fe;

/// `d = -39081` as 56-bit limbs (`p - 39081`).
pub const D: Fe = [
    72057594037888854,
    72057594037927935,
    72057594037927935,
    72057594037927935,
    72057594037927934,
    72057594037927935,
    72057594037927935,
    72057594037927935,
];

/// The base point, compressed (`y || sign(x) << 7`, 57 bytes).
pub const BASE_COMPRESSED: [u8; 57] = [
    0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98, 0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
    0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a, 0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
    0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b, 0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
    0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69, 0x00,
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

    /// Projective identity check (X == 0 and Y == Z).
    #[cfg(test)]
    pub fn is_identity(&self) -> bool {
        fe::is_nonzero(&self.x) == 0 && fe::to_bytes(&self.y) == fe::to_bytes(&self.z)
    }
}

/// r = p + q via the complete RFC 8032 §5.2.4 addition for a = 1:
/// `A = Z1 Z2`, `B = A^2`, `C = X1 X2`, `D = Y1 Y2`, `E = d C D`,
/// `F = B - E`, `G = B + E`, `H = (X1 + Y1)(X2 + Y2)`,
/// `X3 = A F (H - C - D)`, `Y3 = A G (D - C)`, `Z3 = F G`.
pub fn add(p: &P3, q: &P3) -> P3 {
    let a = fe::mul(&p.z, &q.z);
    let b = fe::sq(&a);
    let c = fe::mul(&p.x, &q.x);
    let d = fe::mul(&p.y, &q.y);
    let e = fe::mul(&D, &fe::mul(&c, &d));
    let f = fe::sub(&b, &e);
    let g = fe::add(&b, &e);
    let h = fe::mul(&fe::add(&p.x, &p.y), &fe::add(&q.x, &q.y));

    let hcd = fe::sub(&fe::sub(&h, &c), &d); // X3 / (A F)
    let dc = fe::sub(&d, &c); // Y3 / (A G)

    let x = fe::mul(&fe::mul(&a, &f), &hcd);
    let y = fe::mul(&fe::mul(&a, &g), &dc);
    let z = fe::mul(&f, &g);
    // T3 = X3 Y3 / Z3 = A^2 (H - C - D) (D - C)
    let t = fe::mul(&fe::mul(&b, &hcd), &dc);
    P3 { x, y, z, t }
}

/// r = 2 * p via the RFC 8032 §5.2.4 doubling for a = 1:
/// `B = (X1 + Y1)^2`, `C = X1^2`, `D = Y1^2`, `E = C + D`, `H = Z1^2`,
/// `J = E - 2 H`, `X3 = (B - E) J`, `Y3 = E (C - D)`, `Z3 = E J`.
pub fn dbl(p: &P3) -> P3 {
    let b = fe::sq(&fe::add(&p.x, &p.y));
    let c = fe::sq(&p.x);
    let d = fe::sq(&p.y);
    let e = fe::add(&c, &d);
    let h = fe::sq(&p.z);
    let j = fe::sub(&e, &fe::add(&h, &h));

    let be = fe::sub(&b, &e);
    let cd = fe::sub(&c, &d);
    let x = fe::mul(&be, &j);
    let y = fe::mul(&e, &cd);
    let z = fe::mul(&e, &j);
    // T3 = X3 Y3 / Z3 = (B - E)(C - D)
    let t = fe::mul(&be, &cd);
    P3 { x, y, z, t }
}

/// Encode the point: 57 bytes, `y` little-endian with the sign of `x` in
/// bit 455 (the top bit of the final octet).
pub fn to_bytes(p: &P3) -> [u8; 57] {
    let recip = fe::invert(&p.z);
    let x = fe::mul(&p.x, &recip);
    let y = fe::mul(&p.y, &recip);
    let mut s = [0u8; 57];
    s[..56].copy_from_slice(&fe::to_bytes(&y));
    s[56] = fe::is_negative(&x) << 7;
    s
}

/// Decode a 57-byte compressed point (variable time; public input only),
/// mirroring RFC 8032 §5.2.3. Returns `None` for non-decodable inputs.
pub fn from_bytes(s: &[u8; 57]) -> Option<P3> {
    let sign = s[56] >> 7;
    // Bits 448..454 must be zero: y < p < 2^448.
    if s[56] & 0x7f != 0 {
        return None;
    }
    let mut y_bytes = [0u8; 56];
    y_bytes.copy_from_slice(&s[..56]);
    let y = fe::from_bytes(&y_bytes);
    // Reject non-canonical y (>= p).
    if fe::to_bytes(&y) != y_bytes {
        return None;
    }

    // x^2 = (y^2 - 1) / (d y^2 - 1)
    let y2 = fe::sq(&y);
    let u = fe::sub(&y2, &fe::ONE);
    let v = fe::sub(&fe::mul(&D, &y2), &fe::ONE);
    let w = fe::mul(&u, &fe::invert(&v));
    let x = fe::pow_p_plus_1_div_4(&w);

    // v x^2 == u must hold; otherwise no square root exists.
    if fe::is_nonzero(&fe::sub(&fe::mul(&v, &fe::sq(&x)), &u)) != 0 {
        return None;
    }
    if fe::is_nonzero(&x) == 0 && sign == 1 {
        return None;
    }
    let x = if fe::is_negative(&x) != sign {
        fe::neg(&x)
    } else {
        x
    };

    let t = fe::mul(&x, &y);
    Some(P3 { x, y, z: fe::ONE, t })
}

/// Branch-free selection from a 16-entry table.
fn ct_select_table(table: &[P3; 16], index: u8) -> P3 {
    let mut out = [fe::ZERO; 4];
    for (i, entry) in table.iter().enumerate() {
        // mask = all ones iff i == index.
        let neq = ((index as i64) - (i as i64)) | ((i as i64) - (index as i64));
        let mask = ((((neq >> 63) & 1) as u64) ^ 1).wrapping_neg();
        for (k, f) in [&entry.x, &entry.y, &entry.z, &entry.t]
            .into_iter()
            .enumerate()
        {
            for j in 0..8 {
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

/// Constant-time fixed-base scalar multiplication with 4-bit windows.
pub fn scalarmult_base(scalar: &[u8; 57]) -> P3 {
    let base = from_bytes(&BASE_COMPRESSED).expect("base point decodes");
    scalarmult(&base, scalar)
}

/// Constant-time scalar multiplication with 4-bit windows over the
/// 57-byte little-endian scalar (114 nibbles).
pub fn scalarmult(p: &P3, scalar: &[u8; 57]) -> P3 {
    let mut table = [P3::identity(); 16];
    table[1] = *p;
    for i in 2..16 {
        table[i] = add(&table[i - 1], p);
    }

    let mut r = P3::identity();
    for j in (0..114).rev() {
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
    use crate::ed448::sc;

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
        let mut scalar = [0u8; 57];
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

    #[test]
    fn base_point_roundtrip() {
        let b = from_bytes(&BASE_COMPRESSED).unwrap();
        assert_eq!(to_bytes(&b), BASE_COMPRESSED);
    }
}
