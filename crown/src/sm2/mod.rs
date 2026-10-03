//! SM2 elliptic-curve cryptography over SM2-P-256.
//!
//! * digital signature (GM/T 0003.2, [`sign`]/[`verify`]):
//!   ZA = SM3(ENTL || ID || a || b || xG || yG || xA || yA),
//!   e = SM3(ZA || M), r = (e + x1) mod n,
//!   s = ((1 + d)^-1 * (k - r d)) mod n;
//! * public-key encryption (GB/T 32918.4-2016, [`crypt`]);
//! * key exchange with optional confirmation (GB/T 32918.3-2016, [`kap`]).
//!
//! All three reuse the SM3 implementation, which dispatches to the ported
//! x86_64 asm when the `asm` feature is enabled.

pub mod crypt;
pub mod kap;

use crate::bn::Bn;
use crate::ec::{coord32, Curve, Point};
use crate::error::{CryptoError, CryptoResult};
use crate::hash::sm3::sum_sm3;
use crate::rng::Rng;

use alloc::string::String;
use alloc::vec::Vec;
/// Default user identity used for ZA in the GM/T sample vectors.
pub const DEFAULT_ID: &[u8] = b"1234567812345678";

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn bn_hex(s: &str) -> Bn {
    Bn::from_be_bytes(&hex_to_bytes(s))
}

/// SM2-P-256 curve parameters (GM/T 0003.1).
pub fn sm2_curve() -> Curve {
    Curve::from_parts(
        bn_hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
        bn_hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"),
        bn_hex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
        bn_hex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
        bn_hex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
        bn_hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
    )
}

/// `ZA = SM3(ENTL || ID || a || b || xG || yG || xA || yA)` over
/// SM2-P-256.
pub fn compute_za(id: &[u8], pub_key: &Point) -> [u8; 32] {
    compute_za_on(&sm2_curve(), id, pub_key)
}

/// `ZA` over an explicit curve (the GB/T worked examples use the
/// GB/T 32918.1 annex A example curve).
pub fn compute_za_on(c: &Curve, id: &[u8], pub_key: &Point) -> [u8; 32] {
    assert!(pub_key.infinity || pub_key.is_on_curve(c));
    let mut buf = Vec::with_capacity(2 + id.len() + 32 * 6);
    let entl = (id.len() * 8) as u16;
    buf.extend_from_slice(&entl.to_be_bytes());
    buf.extend_from_slice(id);
    buf.extend_from_slice(&coord32(&c.a));
    buf.extend_from_slice(&coord32(&c.b));
    buf.extend_from_slice(&coord32(&c.gx));
    buf.extend_from_slice(&coord32(&c.gy));
    buf.extend_from_slice(&coord32(&pub_key.x));
    buf.extend_from_slice(&coord32(&pub_key.y));
    sum_sm3(&buf)
}

/// `e = SM3(ZA || M)` as an integer.
fn digest_e(za: &[u8; 32], msg: &[u8]) -> Bn {
    let mut buf = Vec::with_capacity(32 + msg.len());
    buf.extend_from_slice(za);
    buf.extend_from_slice(msg);
    Bn::from_be_bytes(&sum_sm3(&buf))
}

/// Sample `k` in `[1, n-1]`.
pub(crate) fn sample_k(n: &Bn, rng: &mut impl Rng) -> Bn {
    let mut buf = [0u8; 32];
    for _ in 0..128 {
        rng.fill_bytes(&mut buf);
        let k = Bn::from_be_bytes(&buf);
        if !k.is_zero() && k.lt(n) {
            return k;
        }
    }
    Bn::one()
}

/// SM2 signature: `sign(d, msg, id, rng) -> (r, s)`.
pub fn sign(d: &Bn, msg: &[u8], id: &[u8], rng: &mut impl Rng) -> CryptoResult<(Bn, Bn)> {
    let c = sm2_curve();
    let n = &c.n;
    let d = d.modulus(n);
    if d.is_zero() {
        return Err(CryptoError::StrError("sm2: private key out of range"));
    }
    let pub_key = crate::ec::mul_base(&c, &d);
    let za = compute_za(id, &pub_key);
    let e = digest_e(&za, msg);

    for _ in 0..128 {
        let k = sample_k(n, rng);
        let kg = crate::ec::mul_base(&c, &k);
        if kg.is_infinity() {
            continue;
        }
        let x1 = kg.x.modulus(n);
        let r = e.add(&x1).modulus(n);
        if r.is_zero() {
            continue;
        }
        // t = r + k mod n == 0  =>  restart
        let t = r.add(&k).modulus(n);
        if t.is_zero() {
            continue;
        }
        // s = (1+d)^-1 * (k - r d) mod n
        let one_plus_d = d.add(&Bn::one()).modulus(n);
        let inv = one_plus_d.mod_inverse(n)?;
        let rd = r.modmul(&d, n);
        // k - r d (mod n)
        let k_minus_rd = if k.lt(&rd) {
            n.sub(&rd.sub(&k)?)?
        } else {
            k.sub(&rd)?
        };
        let s = inv.modmul(&k_minus_rd, n);
        if s.is_zero() {
            continue;
        }
        return Ok((r, s));
    }
    Err(CryptoError::StrError("sm2: failed to produce signature"))
}

/// SM2 signature: `sign` with the default GM/T identity.
pub fn sign_default_id(d: &Bn, msg: &[u8], rng: &mut impl Rng) -> CryptoResult<(Bn, Bn)> {
    sign(d, msg, DEFAULT_ID, rng)
}

/// SM2 verification: `verify(pub_key, msg, id, r, s)`.
pub fn verify(pub_key: &Point, msg: &[u8], id: &[u8], r: &Bn, s: &Bn) -> CryptoResult<bool> {
    let c = sm2_curve();
    let n = &c.n;
    if pub_key.is_infinity() || !pub_key.is_on_curve(&c) {
        return Ok(false);
    }
    if r.is_zero() || !r.lt(n) || s.is_zero() || !s.lt(n) {
        return Ok(false);
    }
    let za = compute_za(id, pub_key);
    let e = digest_e(&za, msg);
    let t = r.add(s).modulus(n);
    if t.is_zero() {
        return Ok(false);
    }
    let g = crate::ec::generator(&c);
    let sg = g.mul_with(&c, s);
    let tp = pub_key.mul_with(&c, &t);
    let point = sg.add_with(&c, &tp);
    if point.is_infinity() {
        return Ok(false);
    }
    let x1 = point.x.modulus(n);
    let rr = e.add(&x1).modulus(n);
    Ok(rr.eq(r))
}

/// `verify` with the default GM/T identity.
pub fn verify_default_id(pub_key: &Point, msg: &[u8], r: &Bn, s: &Bn) -> CryptoResult<bool> {
    verify(pub_key, msg, DEFAULT_ID, r, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedK {
        k: Vec<u8>,
        used: bool,
    }
    impl Rng for FixedK {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            if !self.used {
                let n = out.len().min(self.k.len());
                out[..n].copy_from_slice(&self.k[..n]);
                self.used = true;
            } else {
                for b in out.iter_mut() {
                    *b = 0;
                }
            }
        }
    }

    /// GM/T 0003.5 sample: d, M = "message digest", ID = "1234567812345678".
    #[test]
    fn gmt_sample_message_digest() {
        let d = bn_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        // Sample k from the GM/T 0003.5 appendix.
        let k = bn_hex("59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21");
        let msg = b"message digest";

        let c = sm2_curve();
        let pub_key = crate::ec::mul_base(&c, &d);
        // Public key from the GM/T sample.
        let expect_x = bn_hex("09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020");
        let expect_y = bn_hex("CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13");
        assert_eq!(coord32(&pub_key.x), coord32(&expect_x), "Px");
        assert_eq!(coord32(&pub_key.y), coord32(&expect_y), "Py");

        let mut rng = FixedK {
            k: k.to_be_bytes_padded(32).unwrap(),
            used: false,
        };
        let (r, s) = sign_default_id(&d, msg, &mut rng).unwrap();

        // Expected signature from GM/T 0003.5.
        let expect_r = bn_hex("F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3");
        let expect_s = bn_hex("B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA");
        assert_eq!(coord32(&r), coord32(&expect_r), "r");
        assert_eq!(coord32(&s), coord32(&expect_s), "s");

        assert!(verify_default_id(&pub_key, msg, &r, &s).unwrap());
        assert!(!verify_default_id(&pub_key, b"other", &r, &s).unwrap());
    }

    /// Sign/verify roundtrip with a random nonce.
    #[test]
    fn sign_verify_roundtrip() {
        struct CounterRng(u64);
        impl Rng for CounterRng {
            fn fill_bytes(&mut self, out: &mut [u8]) {
                for b in out.iter_mut() {
                    self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *b = (self.0 >> 33) as u8;
                }
            }
        }
        let mut rng = CounterRng(0x0bad_c0de_0bad_c0de);
        let c = sm2_curve();
        let d = bn_hex("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
        let pub_key = crate::ec::mul_base(&c, &d);
        let msg = b"sm2 roundtrip message";
        let (r, s) = sign_default_id(&d, msg, &mut rng).unwrap();
        assert!(verify_default_id(&pub_key, msg, &r, &s).unwrap());
        assert!(!verify_default_id(&pub_key, b"tampered", &r, &s).unwrap());
    }

    /// ZA for the GM/T sample identity/public key.
    #[test]
    fn za_known_value() {
        let c = sm2_curve();
        let d = bn_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let pub_key = crate::ec::mul_base(&c, &d);
        let za = compute_za(DEFAULT_ID, &pub_key);
        let expect =
            hex_to_bytes("B2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3");
        assert_eq!(&za[..], &expect[..], "ZA");
    }
}
