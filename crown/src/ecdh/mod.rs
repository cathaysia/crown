//! Elliptic Curve Diffie-Hellman (NIST SP 800-56A style).
//!
//! Shared secret is the 32-byte big-endian X coordinate of `d * peer`
//! (RFC 5903 §7).

use crate::bn::Bn;
use crate::ec::{curve, mul_base, CurveId, Point};
use crate::error::{CryptoError, CryptoResult};
use crate::rsa::Rng;

/// Generate a P-256 key pair `(private, public)`.
pub fn generate(id: CurveId, rng: &mut impl Rng) -> CryptoResult<(Bn, Point)> {
    let c = curve(id);
    // Sample a private scalar in [1, n-1].
    let mut buf = [0u8; 32];
    let mut d = Bn::zero();
    for _ in 0..128 {
        rng.fill_bytes(&mut buf);
        d = Bn::from_be_bytes(&buf);
        if !d.is_zero() && d.lt(&c.n) {
            break;
        }
    }
    if d.is_zero() || !d.lt(&c.n) {
        return Err(CryptoError::StrError("ecdh: failed to sample private key"));
    }
    let pub_point = mul_base(&c, &d);
    Ok((d, pub_point))
}

/// Compute the shared secret: 32-byte big-endian X of `private * peer`.
pub fn agree(private: &Bn, peer: &Point) -> CryptoResult<[u8; 32]> {
    let c = curve(CurveId::P256);
    if peer.is_infinity() || !peer.is_on_curve(&c) {
        return Err(CryptoError::StrError("ecdh: invalid peer point"));
    }
    let d = private.modulus(&c.n);
    if d.is_zero() {
        return Err(CryptoError::StrError("ecdh: private key out of range"));
    }
    let shared = peer.mul_with(&c, &d);
    if shared.is_infinity() {
        return Err(CryptoError::StrError("ecdh: shared point at infinity"));
    }
    let x = crate::ec::coord32(&shared.x);
    Ok(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::Bn;

    fn bn_hex(s: &str) -> Bn {
        let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        Bn::from_be_bytes(&bytes)
    }

    /// RFC 5903 §8.1 — 256-bit Random ECP Group.
    /// Shared secret is `girx`.
    #[test]
    fn rfc5903_p256() {
        let c = curve(CurveId::P256);

        let i = bn_hex("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
        let r = bn_hex("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53");

        // Public keys from the RFC.
        let gix = bn_hex("DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180");
        let giy = bn_hex("5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3");
        let grx = bn_hex("D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63");
        let gry = bn_hex("56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB");

        // Recompute public keys from the private scalars.
        let pub_i = mul_base(&c, &i);
        let pub_r = mul_base(&c, &r);
        assert_eq!(crate::ec::coord32(&pub_i.x), crate::ec::coord32(&gix));
        assert_eq!(crate::ec::coord32(&pub_i.y), crate::ec::coord32(&giy));
        assert_eq!(crate::ec::coord32(&pub_r.x), crate::ec::coord32(&grx));
        assert_eq!(crate::ec::coord32(&pub_r.y), crate::ec::coord32(&gry));

        let shared_girx =
            bn_hex("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");

        let s1 = agree(&i, &pub_r).unwrap();
        let s2 = agree(&r, &pub_i).unwrap();
        assert_eq!(s1, s2, "both sides must agree");
        assert_eq!(s1, crate::ec::coord32(&shared_girx), "RFC 5903 girx");
    }

    /// Key generation produces a valid pair on the curve.
    #[test]
    fn generate_roundtrip() {
        struct CounterRng(u64);
        impl Rng for CounterRng {
            fn fill_bytes(&mut self, out: &mut [u8]) {
                for b in out.iter_mut() {
                    self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *b = (self.0 >> 33) as u8;
                }
            }
        }
        let mut rng = CounterRng(0x1234_5678_9abc_def0);
        let (d1, p1) = generate(CurveId::P256, &mut rng).unwrap();
        let (d2, p2) = generate(CurveId::P256, &mut rng).unwrap();
        assert!(p1.is_on_curve(&curve(CurveId::P256)));
        assert!(p2.is_on_curve(&curve(CurveId::P256)));
        let s12 = agree(&d1, &p2).unwrap();
        let s21 = agree(&d2, &p1).unwrap();
        assert_eq!(s12, s21);
    }
}
