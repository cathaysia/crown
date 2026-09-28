//! Tests for the ecp_nistz256 x86_64 assembly against the software path.
//!
//! Gated on `feature = "asm"` + `target_arch = "x86_64"`; the module is
//! empty otherwise.

#![cfg(all(feature = "asm", target_arch = "x86_64"))]

use super::asm;
use crate::bn::{Bn, Montgomery};
use crate::ec::{curve, generator, CurveId, Point};

fn bn_from_limbs(l: &[u64]) -> Bn {
    let mut be = Vec::with_capacity(l.len() * 8);
    for limb in l.iter().rev() {
        be.extend_from_slice(&limb.to_be_bytes());
    }
    Bn::from_be_bytes(&be)
}

fn limbs_from_bn(v: &Bn) -> [u64; 4] {
    let be = v.to_be_bytes_padded(32).unwrap();
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = u64::from_be_bytes(be[be.len() - (i + 1) * 8..be.len() - i * 8].try_into().unwrap());
    }
    out
}

fn hex_bn(s: &str) -> Bn {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    Bn::from_be_bytes(&bytes)
}

fn p256() -> crate::ec::Curve {
    curve(CurveId::P256)
}

/// P-256 prime as 4 LE limbs.
fn p_limbs() -> [u64; 4] {
    limbs_from_bn(&p256().p)
}

/// P-256 order as 4 LE limbs.
fn n_limbs() -> [u64; 4] {
    limbs_from_bn(&p256().n)
}

// ---- field ops vs Bn mod p ----

#[test]
fn field_add_sub_neg() {
    let c = p256();
    let p = &c.p;
    let a = hex_bn("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFE");
    let b = hex_bn("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    let al = limbs_from_bn(&a);
    let bl = limbs_from_bn(&b);

    let sum = asm::add(&al, &bl);
    assert_eq!(bn_from_limbs(&sum), a.add(&b).modulus(p), "add");

    let diff = asm::sub(&al, &bl);
    assert_eq!(bn_from_limbs(&diff), a.add(p).sub(&b).unwrap().modulus(p), "sub");

    let neg = asm::neg(&al);
    assert_eq!(bn_from_limbs(&neg), p.sub(&a).unwrap(), "neg");
}

#[test]
fn field_mul_by_2_3_div_by_2() {
    let c = p256();
    let p = &c.p;
    let a = hex_bn("123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0");
    let al = limbs_from_bn(&a);

    let dbl = asm::mul_by_2(&al);
    assert_eq!(bn_from_limbs(&dbl), a.add(&a).modulus(p), "mul_by_2");

    let tpl = asm::mul_by_3(&al);
    assert_eq!(
        bn_from_limbs(&tpl),
        a.add(&a).add(&a).modulus(p),
        "mul_by_3"
    );

    // div_by_2(a) == mul_by_2(div_by_2(a)) == a  (p is odd)
    let half = asm::div_by_2(&al);
    let back = asm::mul_by_2(&half);
    assert_eq!(bn_from_limbs(&back), a.modulus(p), "div_by_2 roundtrip");
}

// ---- Montgomery ops (mod p, R = 2^256) ----

#[test]
fn mont_mul_sqr_roundtrip() {
    let c = p256();
    let a = hex_bn("DEADBEEFCAFE0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123");
    let b = hex_bn("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
    let a = a.modulus(&c.p);
    let b = b.modulus(&c.p);

    // to_mont -> mul_mont -> from_mont  ==  a*b mod p
    let am = asm::to_mont(&limbs_from_bn(&a));
    let bm = asm::to_mont(&limbs_from_bn(&b));
    let prod_m = asm::mul_mont(&am, &bm);
    let prod = bn_from_limbs(&asm::from_mont(&prod_m));
    assert_eq!(prod, a.modmul(&b, &c.p), "mul_mont");

    let sq_m = asm::sqr_mont(&am);
    let sq = bn_from_limbs(&asm::from_mont(&sq_m));
    assert_eq!(sq, a.modmul(&a, &c.p), "sqr_mont");

    // to_mont / from_mont roundtrip
    let rt = bn_from_limbs(&asm::from_mont(&am));
    assert_eq!(rt, a, "to/from_mont roundtrip");

    // to_mont(x) == x * R mod p  (R = 2^256 mod p)
    let r_mod = {
        let two256 = Bn::one();
        // 2^256 = 1 << 256
        let mut t = Bn::one();
        for _ in 0..256 {
            t = t.add(&t);
        }
        let _ = two256;
        t.modulus(&c.p)
    };
    let expect_mont = a.modmul(&r_mod, &c.p);
    assert_eq!(bn_from_limbs(&am), expect_mont, "to_mont = x*R");
}

#[test]
fn mont_matches_bn_montgomery() {
    let c = p256();
    let mont = Montgomery::new(&c.p).unwrap();
    let a = hex_bn("1111111111111111111111111111111111111111111111111111111111111111");
    let b = hex_bn("2222222222222222222222222222222222222222222222222222222222222222");
    let a = a.modulus(&c.p);
    let b = b.modulus(&c.p);

    let am = limbs_from_bn(&mont.to_mont(&a));
    let bm = limbs_from_bn(&mont.to_mont(&b));

    // Both sides are Montgomery-form products (a*b*R mod p).
    let got = bn_from_limbs(&asm::mul_mont(&am, &bm));
    let want = mont.mul(&mont.to_mont(&a), &mont.to_mont(&b));
    assert_eq!(got, want.modulus(&c.p), "mul_mont vs Montgomery");
}

// ---- order ops (mod n, R = 2^256) ----

#[test]
fn ord_mul_sqr() {
    let c = p256();
    let mont = Montgomery::new(&c.n).unwrap();
    let a = hex_bn("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
    let b = hex_bn("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53");
    let a = a.modulus(&c.n);
    let b = b.modulus(&c.n);

    let am = limbs_from_bn(&mont.to_mont(&a));
    let bm = limbs_from_bn(&mont.to_mont(&b));

    // Both sides Montgomery-form.
    let prod = bn_from_limbs(&asm::ord_mul_mont(&am, &bm));
    let want = mont.mul(&mont.to_mont(&a), &mont.to_mont(&b));
    assert_eq!(prod, want.modulus(&c.n), "ord_mul_mont");

    let sq = bn_from_limbs(&asm::ord_sqr_mont(&am, 1));
    let want_sq = mont.mul(&mont.to_mont(&a), &mont.to_mont(&a));
    assert_eq!(sq, want_sq.modulus(&c.n), "ord_sqr_mont rep=1");
}

// ---- scatter / gather ----

#[test]
fn scatter_gather_w5_roundtrip() {
    // 16 Jacobian points in a w5 table; index is 1-based.
    let mut table = vec![0u64; 16 * asm::P256_POINT_LIMBS];
    for idx in 1..=16i32 {
        let mut pt = [0u64; 12];
        for (j, limb) in pt.iter_mut().enumerate() {
            *limb = (idx as u64) << 32 | j as u64;
        }
        asm::scatter_w5(&mut table, &pt, idx);
    }
    for idx in 1..=16i32 {
        let mut got = [0u64; 12];
        asm::gather_w5(&mut got, &table, idx);
        for (j, limb) in got.iter().enumerate() {
            assert_eq!(*limb, (idx as u64) << 32 | j as u64, "w5 idx={idx} limb={j}");
        }
    }
}

#[test]
fn scatter_gather_w7_roundtrip() {
    // 64 affine points; scatter is 0-based, gather is 1-based.
    let mut table = vec![0u64; 64 * asm::P256_POINT_AFFINE_LIMBS];
    for k in 0..64i32 {
        let mut pt = [0u64; 8];
        for (j, limb) in pt.iter_mut().enumerate() {
            *limb = (k as u64) << 32 | j as u64;
        }
        asm::scatter_w7(&mut table, &pt, k);
    }
    for k in 0..64i32 {
        let mut got = [0u64; 8];
        asm::gather_w7(&mut got, &table, k + 1);
        for (j, limb) in got.iter().enumerate() {
            assert_eq!(*limb, (k as u64) << 32 | j as u64, "w7 k={k} limb={j}");
        }
    }
}

// ---- point ops vs software Jacobian ----

/// Convert an affine point to Montgomery-form Jacobian (X, Y, Z=1).
fn affine_to_mont_jac(p: &Point) -> [u64; 12] {
    let c = p256();
    let mont = Montgomery::new(&c.p).unwrap();
    let xm = limbs_from_bn(&mont.to_mont(&p.x.modulus(&c.p)));
    let ym = limbs_from_bn(&mont.to_mont(&p.y.modulus(&c.p)));
    let zm = limbs_from_bn(&mont.to_mont(&Bn::one()));
    let mut out = [0u64; 12];
    out[0..4].copy_from_slice(&xm);
    out[4..8].copy_from_slice(&ym);
    out[8..12].copy_from_slice(&zm);
    out
}

/// Convert Montgomery-form Jacobian back to an affine Point.
fn mont_jac_to_affine(j: &[u64; 12]) -> Point {
    let c = p256();
    let mont = Montgomery::new(&c.p).unwrap();
    let p = &c.p;
    let xl: [u64; 4] = j[0..4].try_into().unwrap();
    let yl: [u64; 4] = j[4..8].try_into().unwrap();
    let zl: [u64; 4] = j[8..12].try_into().unwrap();
    let x = bn_from_limbs(&xl);
    let y = bn_from_limbs(&yl);
    let z = bn_from_limbs(&zl);
    // Out of Montgomery form first.
    let x = mont.from_mont(&x).modulus(p);
    let y = mont.from_mont(&y).modulus(p);
    let z = mont.from_mont(&z).modulus(p);
    if z.is_zero() {
        return Point::infinity();
    }
    let zinv = z.mod_inverse(p).unwrap();
    let zinv2 = zinv.modmul(&zinv, p);
    let zinv3 = zinv2.modmul(&zinv, p);
    Point {
        x: x.modmul(&zinv2, p),
        y: y.modmul(&zinv3, p),
        infinity: false,
    }
}

#[test]
fn point_double_matches_software() {
    let c = p256();
    let g = generator(&c);
    let j = affine_to_mont_jac(&g);
    let dbl = asm::point_double(&j);
    let got = mont_jac_to_affine(&dbl);
    let want = g.add_with(&c, &g);
    assert!(!got.is_infinity());
    assert_eq!(got.x.modulus(&c.p), want.x.modulus(&c.p), "2G.x");
    assert_eq!(got.y.modulus(&c.p), want.y.modulus(&c.p), "2G.y");
}

#[test]
fn point_add_matches_software() {
    let c = p256();
    let g = generator(&c);
    let g2 = g.add_with(&c, &g);
    let ja = affine_to_mont_jac(&g);
    let jb = affine_to_mont_jac(&g2);
    let sum = asm::point_add(&ja, &jb);
    let got = mont_jac_to_affine(&sum);
    let want = g.add_with(&c, &g2);
    assert!(!got.is_infinity());
    assert_eq!(got.x.modulus(&c.p), want.x.modulus(&c.p), "(G+2G).x");
    assert_eq!(got.y.modulus(&c.p), want.y.modulus(&c.p), "(G+2G).y");
}

#[test]
fn point_add_affine_matches_software() {
    let c = p256();
    let g = generator(&c);
    let g2 = g.add_with(&c, &g);
    let ja = affine_to_mont_jac(&g);
    let mont = Montgomery::new(&c.p).unwrap();
    let bx = limbs_from_bn(&mont.to_mont(&g2.x.modulus(&c.p)));
    let by = limbs_from_bn(&mont.to_mont(&g2.y.modulus(&c.p)));
    let mut b_aff = [0u64; 8];
    b_aff[0..4].copy_from_slice(&bx);
    b_aff[4..8].copy_from_slice(&by);
    let sum = asm::point_add_affine(&ja, &b_aff);
    let got = mont_jac_to_affine(&sum);
    let want = g.add_with(&c, &g2);
    assert!(!got.is_infinity());
    assert_eq!(got.x.modulus(&c.p), want.x.modulus(&c.p), "affine add x");
    assert_eq!(got.y.modulus(&c.p), want.y.modulus(&c.p), "affine add y");
}

#[test]
fn point_double_three_g() {
    // 2G + G = 3G via asm, compared to software 3G.
    let c = p256();
    let g = generator(&c);
    let g2 = g.add_with(&c, &g);
    let g3 = g2.add_with(&c, &g);
    let j2 = affine_to_mont_jac(&g2);
    let j1 = affine_to_mont_jac(&g);
    let sum = asm::point_add(&j2, &j1);
    let got = mont_jac_to_affine(&sum);
    assert_eq!(got.x.modulus(&c.p), g3.x.modulus(&c.p), "3G.x");
    assert_eq!(got.y.modulus(&c.p), g3.y.modulus(&c.p), "3G.y");
}

// ---- RFC 5903 §8.1 P-256 KAT via repeated doubling + add ----

#[test]
fn rfc5903_p256_scalar_mult_via_asm_point_ops() {
    let c = p256();
    let i = hex_bn("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
    let gix = hex_bn("DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180");
    let giy = hex_bn("5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3");

    // Scalar mult via double-and-add using only the asm point ops.
    let g = generator(&c);
    let bits = i.modulus(&c.n).bit_len();
    let kmod = i.modulus(&c.n);
    // acc = 1*G as Montgomery Jacobian
    let mut acc = affine_to_mont_jac(&g);
    let one_jac = acc;
    for b in (0..bits - 1).rev() {
        acc = asm::point_double(&acc);
        if kmod.bit(b) {
            acc = asm::point_add(&acc, &one_jac);
        }
    }
    let got = mont_jac_to_affine(&acc);
    assert!(!got.is_infinity());
    assert_eq!(got.x.modulus(&c.p), gix, "gix");
    assert_eq!(got.y.modulus(&c.p), giy, "giy");
}

// ---- ord_sqr_mont rep > 1 ----

#[test]
fn ord_sqr_mont_rep_matches_repeated() {
    let c = p256();
    let mont = Montgomery::new(&c.n).unwrap();
    let a = hex_bn("5555555555555555555555555555555555555555555555555555555555555555");
    let a = a.modulus(&c.n);
    let am = limbs_from_bn(&mont.to_mont(&a));

    // rep=3: a^8 in Montgomery domain (both sides stay in Montgomery form).
    let got = bn_from_limbs(&asm::ord_sqr_mont(&am, 3));
    let mut t = mont.to_mont(&a);
    for _ in 0..3 {
        t = mont.mul(&t, &t);
    }
    assert_eq!(got, t.modulus(&c.n), "ord_sqr_mont rep=3");
}
