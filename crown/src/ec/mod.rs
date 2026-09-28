//! Short-Weierstrass elliptic curves over [`Bn`] (Jacobian coordinates).
//!
//! P-256 only for now. Curve parameters follow FIPS 186-4 D.1.2.3.

use crate::bn::Bn;
use crate::error::{CryptoError, CryptoResult};

/// Supported curve identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveId {
    P256,
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

/// Construct curve parameters by id. P-256 constants from FIPS 186-4 D.1.2.3.
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
    }
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

// ---- modular helpers -------------------------------------------------------

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

    /// Point addition. P-256 (the only curve currently supported).
    pub fn add(&self, o: &Point) -> Point {
        let c = curve(CurveId::P256);
        self.add_with(&c, o)
    }

    /// Scalar multiplication. P-256 (the only curve currently supported).
    pub fn mul(&self, k: &Bn) -> Point {
        let c = curve(CurveId::P256);
        self.mul_with(&c, k)
    }

    /// Uncompressed SEC1 encoding: `0x04 || X || Y` (32-byte coordinates).
    /// Point at infinity encodes as a single `0x00` byte.
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

    /// Parse SEC1 uncompressed (or infinity `0x00`) encoding and check the
    /// point lies on `c`.
    pub fn from_bytes(c: &Curve, b: &[u8]) -> CryptoResult<Point> {
        if b.is_empty() {
            return Err(CryptoError::InvalidParameterStr("ec: empty point encoding"));
        }
        if b.len() == 1 && b[0] == 0x00 {
            return Ok(Point::infinity());
        }
        if b.len() != 65 || b[0] != 0x04 {
            return Err(CryptoError::InvalidParameterStr("ec: bad point encoding"));
        }
        let pt = Point {
            x: Bn::from_be_bytes(&b[1..33]),
            y: Bn::from_be_bytes(&b[33..65]),
            infinity: false,
        };
        if !pt.is_on_curve(c) {
            return Err(CryptoError::InvalidParameterStr("ec: point not on curve"));
        }
        Ok(pt)
    }
}

/// Left-pad to 32 bytes (field elements for P-256-class curves).
fn pad32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    assert!(b.len() <= 32, "field element larger than 32 bytes");
    out[32 - b.len()..].copy_from_slice(b);
    out
}

// ---- Jacobian arithmetic ---------------------------------------------------

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

#[cfg(test)]
mod tests {
    use super::*;

    fn p256() -> Curve {
        curve(CurveId::P256)
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
}
