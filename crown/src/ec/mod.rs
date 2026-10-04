//! Short-Weierstrass elliptic curves over [`Bn`] (Jacobian coordinates).
//!
//! P-256, P-384 and P-521. Curve parameters follow FIPS 186-4 D.1.2.3,
//! D.1.2.4 and D.1.2.5 (secp256r1 / secp384r1 / secp521r1).

use crate::bn::{Bn, Montgomery};
use crate::error::{CryptoError, CryptoResult};

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
pub mod nistz256;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
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
    /// Montgomery context over `p`; the field helpers run every product
    /// through it instead of falling back to `mul + divrem`.
    mont: crate::bn::Montgomery,
    /// Curve coefficient `a` in Montgomery form (a = -3 for the NIST curves).
    /// For P-521 (`fast_field`) it holds the plain value instead.
    a_mont: Bn,
    /// P-521's prime is 2^521 - 1: field products fold by shifts, and the
    /// Jacobian layer runs in the plain (non-Montgomery) domain.
    fast_field: bool,
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    assert!(s.len().is_multiple_of(2), "odd hex length");
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
        // secp256r1, FIPS 186-4 D.1.2.3.
        CurveId::P256 => Curve::from_parts(
            bn_hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
            bn_hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
            bn_hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
            bn_hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
            bn_hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
            bn_hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
        ),
        // secp384r1 / P-384, FIPS 186-4 D.1.2.4.
        CurveId::P384 => Curve::from_parts(
            bn_hex(
                "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE
                 FFFFFFFF 00000000 00000000 FFFFFFFF",
            ),
            bn_hex(
                "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE
                 FFFFFFFF 00000000 00000000 FFFFFFFC",
            ),
            bn_hex(
                "B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112 0314088F 5013875A
                 C656398D 8A2ED19D 2A85C8ED D3EC2AEF",
            ),
            bn_hex(
                "AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B98 59F741E0 82542A38
                 5502F25D BF55296C 3A545E38 72760AB7",
            ),
            bn_hex(
                "3617DE4A 96262C6F 5D9E98BF 9292DC29 F8F41DBD 289A147C E9DA3113 B5F0B8C0
                 0A60B1CE 1D7E819D 7A431D7C 90EA0E5F",
            ),
            bn_hex(
                "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C7634D81 F4372DDF
                 581A0DB2 48B0A77A ECEC196A CCC52973",
            ),
        ),
        // secp521r1 / P-521, FIPS 186-4 D.1.2.5. Field prime is 2^521 - 1.
        CurveId::P521 => {
            let mut c = Curve::from_parts(
                bn_hex(
                    "01FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
                 FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
                 FFFF",
                ),
                bn_hex(
                    "01FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
                 FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
                 FFFC",
                ),
                bn_hex(
                    "0051953E B9618E1C 9A1F929A 21A0B685 40EEA2DA 725B99B3 15F3B8B4 89918EF1
                 09E15619 3951EC7E 937B1652 C0BD3BB1 BF073573 DF883D2C 34F1EF45 1FD46B50
                 3F00",
                ),
                bn_hex(
                    "00C6858E 06B70404 E9CD9E3E CB662395 B4429C64 8139053F B521F828 AF606B4D
                 3DBAA14B 5E77EFE7 5928FE1D C127A2FF A8DE3348 B3C1856A 429BF97E 7E31C2E5
                 BD66",
                ),
                bn_hex(
                    "01183929 6A789A3B C0045C8A 5FB42C7D 1BD998F5 4449579B 446817AF BD17273E
                 662C97EE 72995EF4 2640C550 B9013FAD 0761353C 7086A272 C24088BE 94769FD1
                 6650",
                ),
                bn_hex(
                    "01FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
                 FFFA5186 8783BF2F 966B7FCC 0148F709 A5D03BB5 C9B8899C 47AEBB6F B71E9138
                 6409",
                ),
            );
            // Fast field: plain-domain shifted folding, so `a` stays plain.
            c.fast_field = true;
            c.a_mont = c.a.clone();
            c
        }
    }
}

impl Curve {
    /// Assemble a curve from raw parameters and prepare its Montgomery
    /// field context (used by curves defined outside this module, e.g. SM2).
    pub fn from_parts(p: Bn, a: Bn, b: Bn, gx: Bn, gy: Bn, n: Bn) -> Curve {
        let mont = Montgomery::new(&p).expect("curve prime is odd");
        let a_mont = mont.to_mont(&a);
        Curve {
            mont,
            a_mont,
            p,
            a,
            b,
            gx,
            gy,
            n,
            fast_field: false,
        }
    }
}

/// Byte length of field elements / coordinates for `c` (32 / 48 / 66).
pub fn field_bytes(c: &Curve) -> usize {
    c.p.bit_len().div_ceil(8)
}

/// Affine point on the curve; `infinity` is the point at infinity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Point {
    pub x: Bn,
    pub y: Bn,
    pub infinity: bool,
}

/// Fixed-width field element: `s` limbs of `p` in little-endian order,
/// Montgomery form (value * R mod p) inside the Jacobian layer. The width
/// covers P-521 (9 limbs) plus one guard word; limbs at and above `s` stay
/// zero.
const FE_LIMBS: usize = 10;
type Fe = [u64; FE_LIMBS];

/// Jacobian projective point over [`Fe`]: `(X : Y : Z)`.
#[derive(Clone, Copy)]
struct Jac {
    x: Fe,
    y: Fe,
    z: Fe,
}

fn fe_zero() -> Fe {
    [0u64; FE_LIMBS]
}

fn fe_is_zero(v: &Fe, s: usize) -> bool {
    v[..s].iter().all(|&x| x == 0)
}

fn fe_from_bn(v: &Bn, s: usize) -> Fe {
    let mut r = fe_zero();
    for (i, &x) in v.limbs.iter().take(s).enumerate() {
        r[i] = x;
    }
    r
}

fn fe_to_bn(v: &Fe, s: usize) -> Bn {
    let mut bn = Bn {
        limbs: alloc::vec::Vec::from(&v[..s]),
    };
    bn.normalize();
    bn
}

fn p_limbs(c: &Curve) -> Fe {
    fe_from_bn(&c.p, c.p.limbs.len())
}

/// Enter the Jacobian field domain. Montgomery form for the generic path;
/// the plain value for P-521's fast field.
fn fe_to_mont(v: &Bn, c: &Curve) -> Fe {
    if c.fast_field {
        fe_from_bn(&v.modulus(&c.p), c.p.limbs.len())
    } else {
        fe_from_bn(&c.mont.to_mont(v), c.p.limbs.len())
    }
}

/// Field-domain one (R mod p, or plain 1 for the fast field).
fn fe_one_m(c: &Curve) -> Fe {
    if c.fast_field {
        let mut one = fe_zero();
        one[0] = 1;
        one
    } else {
        fe_to_mont(&Bn::one(), c)
    }
}

/// Reduce a raw `(s + 1)`-word CIOS result (value < 2p) into `out` (< p).
fn fe_finish(raw: &[u64], out: &mut Fe, p: &Fe, s: usize) {
    // raw >= p? Equality counts (raw == p must reduce to zero).
    let mut ge = raw[s] != 0;
    if !ge {
        ge = true;
        for j in (0..s).rev() {
            if raw[j] != p[j] {
                ge = raw[j] > p[j];
                break;
            }
        }
    }
    if ge {
        let mut borrow = 0u64;
        for j in 0..s {
            let (d, b1) = raw[j].overflowing_sub(p[j]);
            let (d, b2) = d.overflowing_sub(borrow);
            borrow = (b1 as u64) | (b2 as u64);
            out[j] = d;
        }
        out[s] = 0;
    } else {
        *out = fe_zero();
        out[..s].copy_from_slice(&raw[..s]);
    }
}

/// Field multiplication into `out` (< p). Allocation-free.
fn fe_mul(a: &Fe, b: &Fe, out: &mut Fe, c: &Curve, scratch: &mut [u64; 2 * FE_LIMBS + 1]) {
    if c.fast_field {
        p521_fe_mul(a, b, out);
    } else {
        let s = c.p.limbs.len();
        c.mont.mont_mul_core(&a[..s], &b[..s], scratch);
        let p = p_limbs(c);
        fe_finish(&scratch[s..2 * s + 1], out, &p, s);
    }
}

/// P-521 field multiply, plain domain: `p = 2^521 - 1` folds every product
/// past 521 bits straight back onto the low end (`2^521 ≡ 1`), replacing
/// the generic CIOS reduction.
fn p521_fe_mul(a: &Fe, b: &Fe, out: &mut Fe) {
    debug_assert!(a[9] == 0 && b[9] == 0);
    // Row-wise schoolbook into u64 limbs with u128 accumulators; the
    // operands are below 2^521, so the product fits in 17 limbs.
    let mut v = [0u64; 18];
    for i in 0..9 {
        let ai = a[i] as u128;
        let mut carry: u128 = 0;
        for j in 0..9 {
            let cur = v[i + j] as u128 + ai * (b[j] as u128) + carry;
            v[i + j] = cur as u64;
            carry = cur >> 64;
        }
        let mut k = i + 9;
        while carry > 0 {
            let cur = v[k] as u128 + carry;
            v[k] = cur as u64;
            carry = cur >> 64;
            k += 1;
        }
    }

    // Fold with 2^521 = 1: split at bit 521 (8 limbs + 9 bits) and add the
    // halves back together until nothing extends past bit 521.
    loop {
        if v[9..18].iter().all(|&x| x == 0) && v[8] <= 0x1ff {
            break;
        }
        // H = value >> 521 (9 limbs are enough for the first fold; later
        // folds see far less).
        let mut h = [0u64; 9];
        for i in 0..9 {
            let lo = if 8 + i < 18 { v[8 + i] >> 9 } else { 0 };
            let hi = if 9 + i < 18 { v[9 + i] << 55 } else { 0 };
            h[i] = lo | hi;
        }
        // L = value & (2^521 - 1).
        v[8] &= 0x1ff;
        for lane in v[9..18].iter_mut() {
            *lane = 0;
        }
        let mut c: u64 = 0;
        for i in 0..9 {
            let (s1, o1) = v[i].overflowing_add(h[i]);
            let (s2, o2) = s1.overflowing_add(c);
            v[i] = s2;
            c = (o1 as u64) | (o2 as u64);
        }
        v[9] = c;
    }

    // Value is now in [0, p]; only p itself (all ones) needs reducing.
    let is_p = v[8] == 0x1ff && v[..8].iter().all(|&x| x == u64::MAX);
    *out = fe_zero();
    if !is_p {
        out[..9].copy_from_slice(&v[..9]);
    }
}

/// `a + b (mod p)` for Montgomery-form `a, b < p`.
fn fe_add(a: &Fe, b: &Fe, out: &mut Fe, p: &Fe, s: usize) {
    let mut sum = [0u64; FE_LIMBS + 1];
    let mut carry = 0u64;
    for j in 0..s {
        let (v, c1) = a[j].overflowing_add(b[j]);
        let (v, c2) = v.overflowing_add(carry);
        sum[j] = v;
        carry = (c1 as u64) | (c2 as u64);
    }
    sum[s] = carry;
    fe_finish(&sum, out, p, s);
}

/// `a - b (mod p)` for Montgomery-form `a, b < p`.
fn fe_sub(a: &Fe, b: &Fe, out: &mut Fe, p: &Fe, s: usize) {
    // a + p - b in (0, 2p), computed in s + 1 words.
    let mut sum = [0u64; FE_LIMBS + 1];
    let mut carry = 0u64;
    for j in 0..s {
        let (v, c1) = a[j].overflowing_add(p[j]);
        let (v, c2) = v.overflowing_add(carry);
        sum[j] = v;
        carry = (c1 as u64) | (c2 as u64);
    }
    sum[s] = carry;
    let mut borrow = 0u64;
    for j in 0..s {
        let (v, b1) = sum[j].overflowing_sub(b[j]);
        let (v, b2) = v.overflowing_sub(borrow);
        sum[j] = v;
        borrow = (b1 as u64) | (b2 as u64);
    }
    sum[s] = sum[s].wrapping_sub(borrow);
    fe_finish(&sum, out, p, s);
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

    /// Affine -> Jacobian (Montgomery form).
    fn to_jac(&self, c: &Curve) -> Jac {
        let one_m = fe_one_m(c);
        if self.infinity {
            Jac {
                x: one_m,
                y: one_m,
                z: fe_zero(),
            }
        } else {
            Jac {
                x: fe_to_mont(&self.x, c),
                y: fe_to_mont(&self.y, c),
                z: one_m,
            }
        }
    }

    /// Jacobian (Montgomery form) -> affine (plain values mod `p`).
    fn from_jac(j: &Jac, c: &Curve) -> Point {
        let s = c.p.limbs.len();
        if fe_is_zero(&j.z, s) {
            return Point::infinity();
        }
        // z is z*R: invert the plain z and re-enter Montgomery form. The
        // fast field keeps values plain, so no conversions happen.
        let z_plain = if c.fast_field {
            fe_to_bn(&j.z, s)
        } else {
            c.mont.from_mont(&fe_to_bn(&j.z, s))
        };
        let zinv = z_plain.mod_inverse(&c.p).expect("Z invertible");
        let zinv = fe_to_mont(&zinv, c);
        let mut scratch = [0u64; 2 * FE_LIMBS + 1];
        let mut zinv2 = fe_zero();
        fe_mul(&zinv, &zinv, &mut zinv2, c, &mut scratch);
        let mut zinv3 = fe_zero();
        fe_mul(&zinv2, &zinv, &mut zinv3, c, &mut scratch);
        let mut x = fe_zero();
        fe_mul(&j.x, &zinv2, &mut x, c, &mut scratch);
        let mut y = fe_zero();
        fe_mul(&j.y, &zinv3, &mut y, c, &mut scratch);
        // Back to plain Bn coordinates; identity for the fast field.
        let (xb, yb) = if c.fast_field {
            (fe_to_bn(&x, s), fe_to_bn(&y, s))
        } else {
            (
                c.mont.from_mont(&fe_to_bn(&x, s)),
                c.mont.from_mont(&fe_to_bn(&y, s)),
            )
        };
        Point {
            x: xb,
            y: yb,
            infinity: false,
        }
    }

    /// Check `y^2 = x^3 + a x + b (mod p)` in Montgomery form.
    pub fn is_on_curve(&self, c: &Curve) -> bool {
        if self.infinity {
            return true;
        }
        let s = c.p.limbs.len();
        let p = p_limbs(c);
        let mut scratch = [0u64; 2 * FE_LIMBS + 1];
        let x = fe_to_mont(&self.x.modulus(&c.p), c);
        let y = fe_to_mont(&self.y.modulus(&c.p), c);
        let a = fe_to_mont(&c.a, c);
        let b = fe_to_mont(&c.b, c);
        let mut lhs = fe_zero();
        fe_mul(&y, &y, &mut lhs, c, &mut scratch);
        let mut x2 = fe_zero();
        fe_mul(&x, &x, &mut x2, c, &mut scratch);
        let mut x3 = fe_zero();
        fe_mul(&x2, &x, &mut x3, c, &mut scratch);
        let mut ax = fe_zero();
        fe_mul(&a, &x, &mut ax, c, &mut scratch);
        let mut rhs = fe_zero();
        fe_add(&x3, &ax, &mut rhs, &p, s);
        let mut rhs2 = fe_zero();
        fe_add(&rhs, &b, &mut rhs2, &p, s);
        lhs == rhs2
    }

    /// Point addition on curve `c`.
    pub fn add_with(&self, c: &Curve, o: &Point) -> Point {
        Point::from_jac(&jac_add(&self.to_jac(c), &o.to_jac(c), c), c)
    }

    /// Scalar multiplication `k * self` on curve `c`.
    ///
    /// P-256 uses the nistz256 windowed assembly when the `asm` feature is
    /// on; every other curve uses the portable 4-bit fixed window below.
    pub fn mul_with(&self, c: &Curve, k: &Bn) -> Point {
        #[cfg(all(feature = "asm", target_arch = "x86_64"))]
        if nistz256::driver::is_p256(c) {
            if let Some(point) = nistz256::driver::mul(self, k, &c.n) {
                return point;
            }
        }
        self.mul_with_soft(c, k)
    }

    /// Portable scalar multiplication `k * self` on curve `c` (4-bit fixed
    /// window, MSB first).
    pub(crate) fn mul_with_soft(&self, c: &Curve, k: &Bn) -> Point {
        let kmod = k.modulus(&c.n);
        if kmod.is_zero() || self.infinity {
            return Point::infinity();
        }
        let bits = kmod.bit_len();
        let self_jac = self.to_jac(c);

        // table[i] = i * self in Jacobian coordinates.
        let mut table = alloc::vec![self_jac; 16];
        for i in 2..16 {
            table[i] = jac_add(&table[i - 1], &self_jac, c);
        }

        let one_m = fe_one_m(c);
        let mut acc = Jac {
            x: one_m,
            y: one_m,
            z: fe_zero(),
        };
        let mut i = bits;
        while i > 0 {
            // consume a 4-bit window
            let w = 4usize.min(i);
            for _ in 0..w {
                acc = jac_dbl(&acc, c);
            }
            let mut nib = 0u8;
            for kk in 0..w {
                if kmod.bit(i - w + kk) {
                    nib |= 1 << kk;
                }
            }
            if nib != 0 {
                acc = jac_add(&acc, &table[nib as usize], c);
            }
            i -= w;
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

fn jac_is_inf(j: &Jac, c: &Curve) -> bool {
    fe_is_zero(&j.z, c.p.limbs.len())
}

/// Generic Jacobian point doubling (`dbl-2001-b`). All coordinates are in
/// Montgomery form; the small constants are applied with additions.
fn jac_dbl(a: &Jac, c: &Curve) -> Jac {
    let s = c.p.limbs.len();
    let p = p_limbs(c);
    let mut scratch = [0u64; 2 * FE_LIMBS + 1];
    if jac_is_inf(a, c) || fe_is_zero(&a.y, s) {
        let one_m = fe_one_m(c);
        return Jac {
            x: one_m,
            y: one_m,
            z: fe_zero(),
        };
    }
    // A = X^2, B = Y^2, C = B^2
    let mut xx = fe_zero();
    fe_mul(&a.x, &a.x, &mut xx, c, &mut scratch);
    let mut yy = fe_zero();
    fe_mul(&a.y, &a.y, &mut yy, c, &mut scratch);
    let mut yyyy = fe_zero();
    fe_mul(&yy, &yy, &mut yyyy, c, &mut scratch);
    let mut zz = fe_zero();
    fe_mul(&a.z, &a.z, &mut zz, c, &mut scratch);
    // S = 4*X*YY
    let mut xyy = fe_zero();
    fe_mul(&a.x, &yy, &mut xyy, c, &mut scratch);
    let mut xyy2 = fe_zero();
    fe_add(&xyy, &xyy, &mut xyy2, &p, s);
    let mut s_v = fe_zero();
    fe_add(&xyy2, &xyy2, &mut s_v, &p, s);
    // M = 3*XX + a*Z^4
    let mut m2 = fe_zero();
    fe_add(&xx, &xx, &mut m2, &p, s);
    let mut m3 = fe_zero();
    fe_add(&m2, &xx, &mut m3, &p, s);
    let m = if c.a.is_zero() {
        m3
    } else {
        let mut z4 = fe_zero();
        fe_mul(&zz, &zz, &mut z4, c, &mut scratch);
        let mut az4 = fe_zero();
        let a_m = fe_from_bn(&c.a_mont, s);
        fe_mul(&a_m, &z4, &mut az4, c, &mut scratch);
        let mut m = fe_zero();
        fe_add(&m3, &az4, &mut m, &p, s);
        m
    };
    // T = M^2 - 2*S
    let mut msq = fe_zero();
    fe_mul(&m, &m, &mut msq, c, &mut scratch);
    let mut s2 = fe_zero();
    fe_add(&s_v, &s_v, &mut s2, &p, s);
    let mut t = fe_zero();
    fe_sub(&msq, &s2, &mut t, &p, s);
    let x3 = t;
    // Y3 = M*(S-T) - 8*YYYY
    let mut st = fe_zero();
    fe_sub(&s_v, &x3, &mut st, &p, s);
    let mut mst = fe_zero();
    fe_mul(&m, &st, &mut mst, c, &mut scratch);
    let mut yyyy2 = fe_zero();
    fe_add(&yyyy, &yyyy, &mut yyyy2, &p, s);
    let mut yyyy4 = fe_zero();
    fe_add(&yyyy2, &yyyy2, &mut yyyy4, &p, s);
    let mut yyyy8 = fe_zero();
    fe_add(&yyyy4, &yyyy4, &mut yyyy8, &p, s);
    let mut y3 = fe_zero();
    fe_sub(&mst, &yyyy8, &mut y3, &p, s);
    // Z3 = 2*Y*Z
    let mut y2 = fe_zero();
    fe_add(&a.y, &a.y, &mut y2, &p, s);
    let mut z3 = fe_zero();
    fe_mul(&y2, &a.z, &mut z3, c, &mut scratch);
    Jac {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Generic Jacobian point addition (`add-2007-bl`).
fn jac_add(a: &Jac, b: &Jac, c: &Curve) -> Jac {
    let s = c.p.limbs.len();
    let p = p_limbs(c);
    let mut scratch = [0u64; 2 * FE_LIMBS + 1];
    if jac_is_inf(a, c) {
        return *b;
    }
    if jac_is_inf(b, c) {
        return *a;
    }
    let mut z1z1 = fe_zero();
    fe_mul(&a.z, &a.z, &mut z1z1, c, &mut scratch);
    let mut z2z2 = fe_zero();
    fe_mul(&b.z, &b.z, &mut z2z2, c, &mut scratch);
    let mut u1 = fe_zero();
    fe_mul(&a.x, &z2z2, &mut u1, c, &mut scratch);
    let mut u2 = fe_zero();
    fe_mul(&b.x, &z1z1, &mut u2, c, &mut scratch);
    let mut bz2 = fe_zero();
    fe_mul(&b.z, &z2z2, &mut bz2, c, &mut scratch);
    let mut s1 = fe_zero();
    fe_mul(&a.y, &bz2, &mut s1, c, &mut scratch);
    let mut az1 = fe_zero();
    fe_mul(&a.z, &z1z1, &mut az1, c, &mut scratch);
    let mut s2 = fe_zero();
    fe_mul(&b.y, &az1, &mut s2, c, &mut scratch);
    let mut h = fe_zero();
    fe_sub(&u2, &u1, &mut h, &p, s);
    let mut r = fe_zero();
    fe_sub(&s2, &s1, &mut r, &p, s);
    if fe_is_zero(&h, s) {
        if fe_is_zero(&r, s) {
            return jac_dbl(a, c);
        }
        let one_m = fe_one_m(c);
        return Jac {
            x: one_m,
            y: one_m,
            z: fe_zero(),
        };
    }
    let mut h2 = fe_zero();
    fe_mul(&h, &h, &mut h2, c, &mut scratch);
    let mut h3 = fe_zero();
    fe_mul(&h2, &h, &mut h3, c, &mut scratch);
    let mut u1h2 = fe_zero();
    fe_mul(&u1, &h2, &mut u1h2, c, &mut scratch);
    // X3 = R^2 - H^3 - 2*U1*H^2
    let mut r2 = fe_zero();
    fe_mul(&r, &r, &mut r2, c, &mut scratch);
    let mut x3 = fe_zero();
    fe_sub(&r2, &h3, &mut x3, &p, s);
    let mut u1h2_2 = fe_zero();
    fe_add(&u1h2, &u1h2, &mut u1h2_2, &p, s);
    let mut x3b = fe_zero();
    fe_sub(&x3, &u1h2_2, &mut x3b, &p, s);
    // Y3 = R*(U1*H^2 - X3) - S1*H^3
    let mut ux = fe_zero();
    fe_sub(&u1h2, &x3b, &mut ux, &p, s);
    let mut rux = fe_zero();
    fe_mul(&r, &ux, &mut rux, c, &mut scratch);
    let mut s1h3 = fe_zero();
    fe_mul(&s1, &h3, &mut s1h3, c, &mut scratch);
    let mut y3 = fe_zero();
    fe_sub(&rux, &s1h3, &mut y3, &p, s);
    // Z3 = Z1*Z2*H
    let mut z1z2 = fe_zero();
    fe_mul(&a.z, &b.z, &mut z1z2, c, &mut scratch);
    let mut z3 = fe_zero();
    fe_mul(&z1z2, &h, &mut z3, c, &mut scratch);
    Jac {
        x: x3b,
        y: y3,
        z: z3,
    }
}

/// Curve generator as an affine [`Point`].
pub fn generator(c: &Curve) -> Point {
    Point {
        x: c.gx.clone(),
        y: c.gy.clone(),
        infinity: false,
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
///
/// P-256 uses the precomputed nistz256 generator table when the `asm`
/// feature is on.
pub fn mul_base(c: &Curve, k: &Bn) -> Point {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    if nistz256::driver::is_p256(c) {
        if let Some(point) = nistz256::driver::mul_base(k, &c.n) {
            return point;
        }
    }
    generator(c).mul_with_soft(c, k)
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
