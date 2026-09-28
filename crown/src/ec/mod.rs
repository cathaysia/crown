//! Short-Weierstrass elliptic curves over [`Bn`] (Jacobian coordinates).
//!
//! P-256, P-384 and P-521. Curve parameters follow FIPS 186-4 D.1.2.3,
//! D.1.2.4 and D.1.2.5 (secp256r1 / secp384r1 / secp521r1).

use crate::bn::Bn;
use crate::error::{CryptoError, CryptoResult};

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub mod nistz256;

/// Supported curve identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveId {
    P256,
    P384,
    P521,
}

/// Curve parameters: `y^2 = x^3 + a x + b (mod p)`, base point `(gx, gy)` of order `n`.
#[derive(Debug, Clone)]
pub struct Curve {
    pub p: Bn,
    pub a: Bn,
    pub b: Bn,
    pub gx: Bn,
    pub gy: Bn,
    pub n: Bn,
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn bn_hex(s: &str) -> Bn {
    Bn::from_be_bytes(&hex_to_bytes(s))
}

/// Construct curve parameters by id.
/// P-256 from FIPS 186-4 D.1.2.3, P-384 from D.1.2.4, P-521 from D.1.2.5.
pub fn curve(id: CurveId) -> Curve {
    match id {
        CurveId::P256 => Curve {
            p: bn_hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
            a: bn_hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
            b: bn_hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
            gx: bn_hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
            gy: bn_hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
            n: bn_hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
        },
        // secp384r1 / P-384, FIPS 186-4 D.1.2.4.
        CurveId::P384 => Curve {
            p: bn_hex(
                "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE
                 FFFFFFFF 00000000 00000000 FFFFFFFF",
            ),
            a: bn_hex(
                "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE
                 FFFFFFFF 00000000 00000000 FFFFFFFC",
            ),
            b: bn_hex(
                "B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112 0314088F 5013875A
                 C656398D 8A2ED19D 2A85C8ED D3EC2AEF",
            ),
            gx: bn_hex(
                "AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B98 59F741E0 82542A38
                 5502F25D BF55296C 3A545E38 72760AB7",
            ),
            gy: bn_hex(
                "3617DE4A 96262C6F 5D9E98BF 9292DC29 F8F41DBD 289A147C E9DA3113 B5F0B8C0
                 0A60B1CE 1D7E819D 7A431D7C 90EA0E5F",
            ),
            n: bn_hex(
                "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C7634D81 F4372DDF
                 581A0DB2 48B0A77A ECEC196A CCC52973",
            ),
        },
        // secp521r1 / P-521, FIPS 186-4 D.1.2.5. Field prime is 2^521 - 1.
        CurveId::P521 => Curve {
            p: bn_hex(
                "01FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
                 FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
                 FFFF",
            ),
            a: bn_hex(
                "01FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
                 FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
                 FFFC",
            ),
            b: bn_hex(
                "0051953E B9618E1C 9A1F929A 21A0B685 40EEA2DA 725B99B3 15F3B8B4 89918EF1
                 09E15619 3951EC7E 937B1652 C0BD3BB1 BF073573 DF883D2C 34F1EF45 1FD46B50
                 3F00",
            ),
            gx: bn_hex(
                "00C6858E 06B70404 E9CD9E3E CB662395 B4429C64 8139053F B521F828 AF606B4D
                 3DBAA14B 5E77EFE7 5928FE1D C127A2FF A8DE3348 B3C1856A 429BF97E 7E31C2E5
                 BD66",
            ),
            gy: bn_hex(
                "01183929 6A789A3B C0045C8A 5FB42C7D 1BD998F5 4449579B 446817AF BD17273E
                 662C97EE 72995EF4 2640C550 B9013FAD 0761353C 7086A272 C24088BE 94769FD1
                 6650",
            ),
            n: bn_hex(
                "01FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
                 FFFA5186 8783BF2F 966B7FCC 0148F709 A5D03BB5 C9B8899C 47AEBB6F B71E9138
                 6409",
            ),
        },
    }
}

/// Byte length of field elements / coordinates for `c` (32 / 48 / 66).
pub fn field_bytes(c: &Curve) -> usize {
    (c.p.bit_len() + 7) / 8
}

/// Affine point on the curve; `infinity` is the point at infinity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Point {
    pub x: Bn,
    pub y: Bn,
    pub infinity: bool,
}

/// Jacobian projective point: `(X : Y : Z)`, affine `(X/Z^2, Y/Z^3)`.
#[derive(Debug, Clone)]
struct Jac {
    x: Bn,
    y: Bn,
    z: Bn,
}


fn madd(a: &Bn, b: &Bn, p: &Bn) -> Bn {
    a.add(b).modulus(p)
}

/// `a - b (mod p)`, safe when `a < b`.
fn msub(a: &Bn, b: &Bn, p: &Bn) -> Bn {
    a.add(p).sub(b).expect("a + p >= b").modulus(p)
}

fn mmul(a: &Bn, b: &Bn, p: &Bn) -> Bn {
    // Bn::modmul is `self * b mod m`
    a.modmul(b, p)
}

fn msqr(a: &Bn, p: &Bn) -> Bn {
    a.modmul(a, p)
}

fn u64_bn(v: u64) -> Bn {
    Bn::from_u64(v)
}

/// Curve base point as a [`Point`].
pub fn generator(c: &Curve) -> Point {
    Point {
        x: c.gx.clone(),
        y: c.gy.clone(),
        infinity: false,
    }
}

impl Point {
    /// The point at infinity.
    pub fn infinity() -> Point {
        Point {
            x: Bn::zero(),
            y: Bn::zero(),
            infinity: true,
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.infinity
    }

    /// Affine -> Jacobian.
    fn to_jac(&self) -> Jac {
        if self.infinity {
            Jac {
                x: Bn::one(),
                y: Bn::one(),
                z: Bn::zero(),
            }
        } else {
            Jac {
                x: self.x.clone(),
                y: self.y.clone(),
                z: Bn::one(),
            }
        }
    }

    /// Jacobian -> affine (reduce mod `p`).
    fn from_jac(j: &Jac, c: &Curve) -> Point {
        if j.z.is_zero() {
            return Point::infinity();
        }
        let p = &c.p;
        let zinv = j.z.mod_inverse(p).expect("Z invertible");
        let zinv2 = msqr(&zinv, p);
        let zinv3 = mmul(&zinv2, &zinv, p);
        Point {
            x: mmul(&j.x, &zinv2, p),
            y: mmul(&j.y, &zinv3, p),
            infinity: false,
        }
    }

    /// Check `y^2 = x^3 + a x + b (mod p)`.
    pub fn is_on_curve(&self, c: &Curve) -> bool {
        if self.infinity {
            return true;
        }
        let p = &c.p;
        let lhs = msqr(&self.y.modulus(p), p);
        let x = self.x.modulus(p);
        let x2 = msqr(&x, p);
        let x3 = mmul(&x2, &x, p);
        let ax = mmul(&c.a, &x, p);
        let rhs = madd(&madd(&x3, &ax, p), &c.b.modulus(p), p);
        lhs == rhs
    }

    /// Point addition on curve `c`.
    pub fn add_with(&self, c: &Curve, o: &Point) -> Point {
        Point::from_jac(&jac_add(&self.to_jac(), &o.to_jac(), c), c)
    }

    /// Scalar multiplication `k * self` on curve `c` (double-and-add, MSB first).
    pub fn mul_with(&self, c: &Curve, k: &Bn) -> Point {
        let kmod = k.modulus(&c.n);
        if kmod.is_zero() || self.infinity {
            return Point::infinity();
        }
        let bits = kmod.bit_len();
        let self_jac = self.to_jac();
        let mut acc = self_jac.clone();
        for i in (0..bits - 1).rev() {
            acc = jac_dbl(&acc, c);
            if kmod.bit(i) {
                acc = jac_add(&acc, &self_jac, c);
            }
        }
        Point::from_jac(&acc, c)
    }

    /// Point addition. P-256 (kept for compatibility).
    pub fn add(&self, o: &Point) -> Point {
        let c = curve(CurveId::P256);
        self.add_with(&c, o)
    }

    /// Scalar multiplication. P-256 (kept for compatibility).
    pub fn mul(&self, k: &Bn) -> Point {
        let c = curve(CurveId::P256);
        self.mul_with(&c, k)
    }

    /// Uncompressed SEC1 encoding on `c`: `0x04 || X || Y` with coordinates
    /// left-padded to the curve field size (32 / 48 / 66 bytes).
    /// Point at infinity encodes as a single `0x00` byte.
    pub fn to_bytes_with(&self, c: &Curve) -> Vec<u8> {
        if self.infinity {
            return vec![0x00];
        }
        let n = field_bytes(c);
        let mut out = Vec::with_capacity(1 + 2 * n);
        out.push(0x04);
        out.extend_from_slice(&pad_to(&self.x.to_be_bytes(), n));
        out.extend_from_slice(&pad_to(&self.y.to_be_bytes(), n));
        out
    }

    /// Uncompressed SEC1 encoding assuming P-256 (32-byte coordinates).
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.infinity {
            return vec![0x00];
        }
        let mut out = Vec::with_capacity(65);
        out.push(0x04);
        out.extend_from_slice(&pad32(&self.x.to_be_bytes()));
        out.extend_from_slice(&pad32(&self.y.to_be_bytes()));
        out
    }

    /// Parse SEC1 uncompressed (or infinity `0x00`) encoding on curve `c`
    /// and check the point lies on `c`.
    pub fn from_bytes(c: &Curve, b: &[u8]) -> CryptoResult<Point> {
        if b.is_empty() {
            return Err(CryptoError::InvalidParameterStr("ec: empty point encoding"));
        }
        if b.len() == 1 && b[0] == 0x00 {
            return Ok(Point::infinity());
        }
        let n = field_bytes(c);
        if b.len() != 1 + 2 * n || b[0] != 0x04 {
            return Err(CryptoError::InvalidParameterStr("ec: bad point encoding"));
        }
        let pt = Point {
            x: Bn::from_be_bytes(&b[1..1 + n]),
            y: Bn::from_be_bytes(&b[1 + n..]),
            infinity: false,
        };
        if !pt.is_on_curve(c) {
            return Err(CryptoError::InvalidParameterStr("ec: point not on curve"));
        }
        Ok(pt)
    }
}

/// Left-pad to `n` bytes.
pub fn pad_to(b: &[u8], n: usize) -> Vec<u8> {
    assert!(b.len() <= n, "field element larger than target width");
    let mut out = vec![0u8; n];
    out[n - b.len()..].copy_from_slice(b);
    out
}

/// Left-pad to 32 bytes (field elements for P-256).
fn pad32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    assert!(b.len() <= 32, "field element larger than 32 bytes");
    out[32 - b.len()..].copy_from_slice(b);
    out
}


fn jac_is_inf(j: &Jac) -> bool {
    j.z.is_zero()
}

/// Generic Jacobian point doubling (`dbl-2001-b`).
fn jac_dbl(a: &Jac, c: &Curve) -> Jac {
    if jac_is_inf(a) || a.y.is_zero() {
        return Jac {
            x: Bn::one(),
            y: Bn::one(),
            z: Bn::zero(),
        };
    }
    let p = &c.p;
    // A = X^2, B = Y^2, C = B^2
    let xx = msqr(&a.x, p);
    let yy = msqr(&a.y, p);
    let yyyy = msqr(&yy, p);
    let zz = msqr(&a.z, p);
    // S = 2*((X+B)^2 - A - C) = 4 X B
    let s = mmul(&u64_bn(4), &mmul(&a.x, &yy, p), p);
    // M = 3*A + a*Z^4
    let mut m = mmul(&u64_bn(3), &xx, p);
    if !c.a.is_zero() {
        let z4 = msqr(&zz, p);
        m = madd(&m, &mmul(&c.a, &z4, p), p);
    }
    // T = M^2 - 2*S
    let t = msub(&msqr(&m, p), &madd(&s, &s, p), p);
    let x3 = t.clone();
    // Y3 = M*(S-T) - 8*YYYY
    let y3 = msub(
        &mmul(&m, &msub(&s, &t, p), p),
        &mmul(&u64_bn(8), &yyyy, p),
        p,
    );
    // Z3 = 2*Y*Z
    let z3 = mmul(&madd(&a.y, &a.y, p), &a.z, p);
    Jac {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Generic Jacobian point addition (`add-2007-bl`).
fn jac_add(a: &Jac, b: &Jac, c: &Curve) -> Jac {
    if jac_is_inf(a) {
        return b.clone();
    }
    if jac_is_inf(b) {
        return a.clone();
    }
    let p = &c.p;
    let z1z1 = msqr(&a.z, p);
    let z2z2 = msqr(&b.z, p);
    let u1 = mmul(&a.x, &z2z2, p);
    let u2 = mmul(&b.x, &z1z1, p);
    let s1 = mmul(&a.y, &mmul(&b.z, &z2z2, p), p);
    let s2 = mmul(&b.y, &mmul(&a.z, &z1z1, p), p);
    let h = msub(&u2, &u1, p);
    let r = msub(&s2, &s1, p);
    if h.is_zero() {
        if r.is_zero() {
            return jac_dbl(a, c);
        }
        return Jac {
            x: Bn::one(),
            y: Bn::one(),
            z: Bn::zero(),
        };
    }
    let h2 = msqr(&h, p);
    let h3 = mmul(&h2, &h, p);
    let u1h2 = mmul(&u1, &h2, p);
    // X3 = R^2 - H^3 - 2*U1*H^2
    let x3 = msub(
        &msub(&msqr(&r, p), &h3, p),
        &madd(&u1h2, &u1h2, p),
        p,
    );
    // Y3 = R*(U1*H^2 - X3) - S1*H^3
    let y3 = msub(
        &mmul(&r, &msub(&u1h2, &x3, p), p),
        &mmul(&s1, &h3, p),
        p,
    );
    let z3 = mmul(&mmul(&a.z, &b.z, p), &h, p);
    Jac {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Free-function point addition on an explicit curve (usable for any
/// short-Weierstrass curve, e.g. SM2-P-256).
pub fn point_add(c: &Curve, a: &Point, b: &Point) -> Point {
    a.add_with(c, b)
}

/// Free-function scalar multiplication on an explicit curve.
pub fn point_mul(c: &Curve, a: &Point, k: &Bn) -> Point {
    a.mul_with(c, k)
}

/// `k * G` on curve `c`.
pub fn mul_base(c: &Curve, k: &Bn) -> Point {
    generator(c).mul_with(c, k)
}

/// Serialize an affine coordinate as exactly 32 big-endian bytes.
pub fn coord32(v: &Bn) -> [u8; 32] {
    pad32(&v.to_be_bytes())
}

/// Serialize an affine coordinate left-padded to `n` bytes.
pub fn coord_padded(v: &Bn, n: usize) -> Vec<u8> {
    pad_to(&v.to_be_bytes(), n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p256() -> Curve {
        curve(CurveId::P256)
    }

    fn test_hex(s: &str) -> Bn {
        bn_hex(s)
    }

    #[test]
    fn n_times_g_is_infinity() {
        let c = p256();
        let r = mul_base(&c, &c.n);
        assert!(r.is_infinity(), "n*G must be infinity");
    }

    #[test]
    fn g_times_one_is_g() {
        let c = p256();
        let g = generator(&c);
        let r = g.mul_with(&c, &Bn::one());
        assert!(!r.is_infinity());
        assert_eq!(coord32(&r.x), coord32(&c.gx));
        assert_eq!(coord32(&r.y), coord32(&c.gy));
    }

    #[test]
    fn two_g_is_g_plus_g() {
        let c = p256();
        let g = generator(&c);
        let g2_mul = g.mul_with(&c, &Bn::from_u64(2));
        let g2_add = g.add_with(&c, &g);
        assert!(!g2_mul.is_infinity());
        assert_eq!(coord32(&g2_mul.x), coord32(&g2_add.x));
        assert_eq!(coord32(&g2_mul.y), coord32(&g2_add.y));
    }

    #[test]
    fn roundtrip_bytes() {
        let c = p256();
        let g = generator(&c);
        let b = g.to_bytes();
        assert_eq!(b.len(), 65);
        assert_eq!(b[0], 0x04);
        let g2 = Point::from_bytes(&c, &b).unwrap();
        assert_eq!(coord32(&g2.x), coord32(&c.gx));
        assert_eq!(coord32(&g2.y), coord32(&c.gy));
    }

    #[test]
    fn g_on_curve() {
        let c = p256();
        assert!(generator(&c).is_on_curve(&c));
    }

    #[test]
    fn add_matches_mul_small() {
        let c = p256();
        let g = generator(&c);
        let three = g.mul_with(&c, &Bn::from_u64(3));
        let g3 = g.add_with(&c, &g.add_with(&c, &g));
        assert_eq!(coord32(&three.x), coord32(&g3.x));
        assert_eq!(coord32(&three.y), coord32(&g3.y));
    }

    fn assert_curve_ops(id: CurveId) {
        let c = curve(id);
        let fb = field_bytes(&c);
        let g = generator(&c);
        assert!(g.is_on_curve(&c), "G on curve");

        // G * 1 = G
        let g1 = g.mul_with(&c, &Bn::one());
        assert!(!g1.is_infinity());
        assert_eq!(coord_padded(&g1.x, fb), coord_padded(&c.gx, fb));
        assert_eq!(coord_padded(&g1.y, fb), coord_padded(&c.gy, fb));

        // 2G = G + G
        let g2_mul = g.mul_with(&c, &Bn::from_u64(2));
        let g2_add = g.add_with(&c, &g);
        assert!(!g2_mul.is_infinity());
        assert_eq!(coord_padded(&g2_mul.x, fb), coord_padded(&g2_add.x, fb));
        assert_eq!(coord_padded(&g2_mul.y, fb), coord_padded(&g2_add.y, fb));

        // n * G = infinity (checked via (n-1)*G + G so mul_with does not
        // short-circuit on k mod n == 0)
        let n_minus_1 = c.n.sub(&Bn::one()).expect("n > 1");
        let nm1_g = mul_base(&c, &n_minus_1);
        let sum = nm1_g.add_with(&c, &g);
        assert!(sum.is_infinity(), "(n-1)*G + G must be infinity");
        assert!(mul_base(&c, &c.n).is_infinity(), "n*G must be infinity");

        // 3G via repeated addition matches scalar mult
        let three = g.mul_with(&c, &Bn::from_u64(3));
        let g3 = g.add_with(&c, &g.add_with(&c, &g));
        assert_eq!(coord_padded(&three.x, fb), coord_padded(&g3.x, fb));
    }

    #[test]
    fn p384_group_ops() {
        assert_curve_ops(CurveId::P384);
    }

    #[test]
    fn p521_group_ops() {
        assert_curve_ops(CurveId::P521);
    }

    #[test]
    fn p384_roundtrip_bytes() {
        let c = curve(CurveId::P384);
        let g = generator(&c);
        let b = g.to_bytes_with(&c);
        assert_eq!(b.len(), 97);
        assert_eq!(b[0], 0x04);
        let g2 = Point::from_bytes(&c, &b).unwrap();
        assert_eq!(coord_padded(&g2.x, 48), coord_padded(&c.gx, 48));
        assert_eq!(coord_padded(&g2.y, 48), coord_padded(&c.gy, 48));
    }

    #[test]
    fn p521_roundtrip_bytes() {
        let c = curve(CurveId::P521);
        let g = generator(&c);
        let b = g.to_bytes_with(&c);
        assert_eq!(b.len(), 133);
        assert_eq!(b[0], 0x04);
        let g2 = Point::from_bytes(&c, &b).unwrap();
        assert_eq!(coord_padded(&g2.x, 66), coord_padded(&c.gx, 66));
        assert_eq!(coord_padded(&g2.y, 66), coord_padded(&c.gy, 66));
    }

    /// RFC 5903 §8.2 — 384-bit group: `i * G` equals the published `(gix, giy)`.
    #[test]
    fn rfc5903_p384_scalar_mult() {
        let c = curve(CurveId::P384);
        let i = test_hex(
            "099F3C70 34D4A2C6 99884D73 A375A67F 7624EF7C 6B3C0F16 0647B674 14DCE655
             E35B5380 41E649EE 3FAEF896 783AB194",
        );
        let gix = test_hex(
            "667842D7 D180AC2C DE6F74F3 7551F557 55C7645C 20EF73E3 1634FE72 B4C55EE6
             DE3AC808 ACB4BDB4 C88732AE E95F41AA",
        );
        let giy = test_hex(
            "9482ED1F C0EEB9CA FC498462 5CCFC23F 65032149 E0E144AD A0241815 35A0F38E
             EB9FCFF3 C2C947DA E69B4C63 4573A81C",
        );
        let pub_i = mul_base(&c, &i);
        assert!(!pub_i.is_infinity());
        assert_eq!(coord_padded(&pub_i.x, 48), coord_padded(&gix, 48), "gix");
        assert_eq!(coord_padded(&pub_i.y, 48), coord_padded(&giy, 48), "giy");
    }

    /// RFC 5903 §8.3 — 521-bit group: `i * G` equals the published `(gix, giy)`.
    #[test]
    fn rfc5903_p521_scalar_mult() {
        let c = curve(CurveId::P521);
        let i = test_hex(
            "0037ADE9 319A89F4 DABDB3EF 411AACCC A5123C61 ACAB57B5 393DCE47 608172A0
             95AA85A3 0FE1C295 2C6771D9 37BA9777 F5957B26 39BAB072 462F68C2 7A57382D
             4A52",
        );
        let gix = test_hex(
            "0015417E 84DBF28C 0AD3C278 713349DC 7DF153C8 97A1891B D98BAB43 57C9ECBE
             E1E3BF42 E00B8E38 0AEAE57C 2D107564 94188594 2AF5A7F4 601723C4 195D176C
             ED3E",
        );
        let giy = test_hex(
            "017CAE20 B6641D2E EB695786 D8C94614 6239D099 E18E1D5A 514C739D 7CB4A10A
             D8A78801 5AC405D7 799DC75E 7B7D5B6C F2261A6A 7F150743 8BF01BEB 6CA3926F
             9582",
        );
        let pub_i = mul_base(&c, &i);
        assert!(!pub_i.is_infinity());
        assert_eq!(coord_padded(&pub_i.x, 66), coord_padded(&gix, 66), "gix");
        assert_eq!(coord_padded(&pub_i.y, 66), coord_padded(&giy, 66), "giy");
    }
}
