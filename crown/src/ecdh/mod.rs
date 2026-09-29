//! Elliptic Curve Diffie-Hellman (NIST SP 800-56A style).
//!
//! Shared secret is the big-endian X coordinate of `d * peer`, left-padded
//! to the curve field size (RFC 5903 §7): 32 bytes for P-256, 48 for P-384,
//! 66 for P-521.

use crate::bn::Bn;
use crate::ec::{curve, field_bytes, mul_base, CurveId, Point};
use crate::error::{CryptoError, CryptoResult};
use crate::rng::Rng;

use alloc::vec;
use alloc::vec::Vec;
/// Generate a key pair `(private, public)` on curve `id`.
pub fn generate(id: CurveId, rng: &mut impl Rng) -> CryptoResult<(Bn, Point)> {
    let c = curve(id);
    // Sample a private scalar in [1, n-1]. Clear the unused high bits so a
    // draw lies in [0, 2^bitlen(n)) and rejection rate stays negligible
    // (matters for P-521, where field bytes are wider than the order).
    let buf_len = field_bytes(&c);
    let n_bits = c.n.bit_len();
    let excess_bits = buf_len * 8 - n_bits;
    let mut buf = vec![0u8; buf_len];
    let mut d = Bn::zero();
    for _ in 0..128 {
        rng.fill_bytes(&mut buf);
        if excess_bits > 0 {
            buf[0] &= 0xffu8 >> excess_bits;
        }
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

/// Compute the shared secret: big-endian X of `private * peer`, left-padded
/// to the curve field size (32 / 48 / 66 bytes).
pub fn agree(id: CurveId, private: &Bn, peer: &Point) -> CryptoResult<Vec<u8>> {
    let c = curve(id);
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
    Ok(crate::ec::coord_padded(&shared.x, field_bytes(&c)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::Bn;

    fn bn_hex(s: &str) -> Bn {
        let s: alloc::string::String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
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

        let s1 = agree(CurveId::P256, &i, &pub_r).unwrap();
        let s2 = agree(CurveId::P256, &r, &pub_i).unwrap();
        assert_eq!(s1, s2, "both sides must agree");
        assert_eq!(s1.len(), 32);
        assert_eq!(
            s1,
            crate::ec::coord32(&shared_girx).to_vec(),
            "RFC 5903 girx"
        );
    }

    /// RFC 5903 §8.2 — 384-bit Random ECP Group.
    #[test]
    fn rfc5903_p384() {
        let c = curve(CurveId::P384);

        let i = bn_hex(
            "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655
             E35B538041E649EE3FAEF896783AB194",
        );
        let r = bn_hex(
            "41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942
             E0308312916B8ED2960E4BD55A7448FC",
        );

        let gix = bn_hex(
            "667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6
             DE3AC808ACB4BDB4C88732AEE95F41AA",
        );
        let giy = bn_hex(
            "9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38E
             EB9FCFF3C2C947DAE69B4C634573A81C",
        );
        let grx = bn_hex(
            "E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D
             0D1AC43A0336DEF96FDA41D0774A3571",
        );
        let gry = bn_hex(
            "DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FF
             F83FA40142209DFF5EAAD96DB9E6386C",
        );

        let pub_i = mul_base(&c, &i);
        let pub_r = mul_base(&c, &r);
        assert_eq!(
            crate::ec::coord_padded(&pub_i.x, 48),
            crate::ec::coord_padded(&gix, 48)
        );
        assert_eq!(
            crate::ec::coord_padded(&pub_i.y, 48),
            crate::ec::coord_padded(&giy, 48)
        );
        assert_eq!(
            crate::ec::coord_padded(&pub_r.x, 48),
            crate::ec::coord_padded(&grx, 48)
        );
        assert_eq!(
            crate::ec::coord_padded(&pub_r.y, 48),
            crate::ec::coord_padded(&gry, 48)
        );

        let shared_girx = bn_hex(
            "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4
             D603135569B9E9D09CF5D4A270F59746",
        );

        let s1 = agree(CurveId::P384, &i, &pub_r).unwrap();
        let s2 = agree(CurveId::P384, &r, &pub_i).unwrap();
        assert_eq!(s1, s2, "both sides must agree");
        assert_eq!(s1.len(), 48);
        assert_eq!(
            s1,
            crate::ec::coord_padded(&shared_girx, 48),
            "RFC 5903 P-384 girx"
        );
    }

    /// RFC 5903 §8.3 — 521-bit Random ECP Group.
    #[test]
    fn rfc5903_p521() {
        let c = curve(CurveId::P521);

        let i = bn_hex(
            "0037ADE9319A89F4DABDB3EF411AACCCA5123C61ACAB57B5393DCE47608172A0
             95AA85A30FE1C2952C6771D937BA9777F5957B2639BAB072462F68C27A57382D
             4A52",
        );
        let r = bn_hex(
            "0145BA99A847AF43793FDD0E872E7CDFA16BE30FDC780F97BCCC3F078380201E
             9C677D600B343757A3BDBF2A3163E4C2F869CCA7458AA4A4EFFC311F5CB15168
             5EB9",
        );

        let shared_girx = bn_hex(
            "01144C7D79AE6956BC8EDB8E7C787C4521CB086FA64407F97894E5E6B2D79B04
             D1427E73CA4BAA240A34786859810C06B3C715A3A8CC3151F2BEE417996D19F3
             DDEA",
        );

        let pub_i = mul_base(&c, &i);
        let pub_r = mul_base(&c, &r);
        assert!(!pub_i.is_infinity() && !pub_r.is_infinity());

        let s1 = agree(CurveId::P521, &i, &pub_r).unwrap();
        let s2 = agree(CurveId::P521, &r, &pub_i).unwrap();
        assert_eq!(s1, s2, "both sides must agree");
        assert_eq!(s1.len(), 66);
        assert_eq!(
            s1,
            crate::ec::coord_padded(&shared_girx, 66),
            "RFC 5903 P-521 girx"
        );
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
        for id in [CurveId::P256, CurveId::P384, CurveId::P521] {
            let (d1, p1) = generate(id, &mut rng).unwrap();
            let (d2, p2) = generate(id, &mut rng).unwrap();
            let c = curve(id);
            assert!(p1.is_on_curve(&c));
            assert!(p2.is_on_curve(&c));
            let s12 = agree(id, &d1, &p2).unwrap();
            let s21 = agree(id, &d2, &p1).unwrap();
            assert_eq!(s12, s21);
            assert_eq!(s12.len(), field_bytes(&c));
        }
    }

    /// Invalid peer points are rejected.
    #[test]
    fn reject_invalid_peer() {
        struct CounterRng(u64);
        impl Rng for CounterRng {
            fn fill_bytes(&mut self, out: &mut [u8]) {
                for b in out.iter_mut() {
                    self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *b = (self.0 >> 33) as u8;
                }
            }
        }
        let mut rng = CounterRng(1);
        let (d, _) = generate(CurveId::P384, &mut rng).unwrap();
        assert!(agree(CurveId::P384, &d, &Point::infinity()).is_err());
    }
}
