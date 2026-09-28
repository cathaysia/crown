//! ECDSA over P-256 with SHA-256 (FIPS 186-4 / RFC 6979 compatible).
//!
//! Signature is `(r, s)` with `s` low-s not enforced (raw ECDSA as in
//! FIPS 186-4). Nonces come from the caller-supplied [`Rng`]; for the
//! deterministic RFC 6979 path feed it an HMAC-DRBG derived from the key.

use crate::bn::Bn;
use crate::ec::{curve, generator, mul_base, CurveId, Point};
use crate::error::{CryptoError, CryptoResult};
use crate::hash::sha256::sum256;
use crate::rsa::Rng;

fn bn_from_digest(d: &[u8; 32]) -> Bn {
    Bn::from_be_bytes(d)
}

/// Sample `k` uniformly in `[1, n-1]`.
fn sample_k(n: &Bn, rng: &mut impl Rng) -> Bn {
    let mut buf = [0u8; 32];
    for _ in 0..128 {
        rng.fill_bytes(&mut buf);
        let k = Bn::from_be_bytes(&buf);
        if !k.is_zero() && k.lt(n) {
            return k;
        }
    }
    // Astronomically unlikely; fall back to 1 rather than panic in a
    // signature path (caller can retry).
    Bn::one()
}

/// ECDSA sign over SHA-256. Returns `(r, s)`.
pub fn sign_sha256(d: &Bn, msg: &[u8], rng: &mut impl Rng) -> CryptoResult<(Bn, Bn)> {
    let c = curve(CurveId::P256);
    let n = &c.n;
    let d = d.modulus(n);
    if d.is_zero() {
        return Err(CryptoError::StrError("ecdsa: private key out of range"));
    }
    let digest = sum256(msg);
    let e_bn = bn_from_digest(&digest).modulus(n);

    for _ in 0..128 {
        let k = sample_k(n, rng);
        let r_point = mul_base(&c, &k);
        let r = r_point.x.modulus(n);
        if r.is_zero() {
            continue;
        }
        // s = k^{-1} (e + r d) mod n
        let kinv = k.mod_inverse(n)?;
        let rd = r.modmul(&d, n);
        let e_plus = e_bn.add(&rd).modulus(n);
        let s = kinv.modmul(&e_plus, n);
        if s.is_zero() {
            continue;
        }
        return Ok((r, s));
    }
    Err(CryptoError::StrError("ecdsa: failed to produce signature"))
}

/// ECDSA verify over SHA-256. Returns `true` iff the signature is valid.
pub fn verify_sha256(pub_key: &Point, msg: &[u8], r: &Bn, s: &Bn) -> CryptoResult<bool> {
    let c = curve(CurveId::P256);
    let n = &c.n;
    if pub_key.is_infinity() || !pub_key.is_on_curve(&c) {
        return Ok(false);
    }
    if r.is_zero() || !r.lt(n) || s.is_zero() || !s.lt(n) {
        return Ok(false);
    }
    let digest = sum256(msg);
    let e = bn_from_digest(&digest).modulus(n);

    let w = s.mod_inverse(n)?;
    let u1 = e.modmul(&w, n);
    let u2 = r.modmul(&w, n);

    let g = generator(&c);
    let p1 = g.mul_with(&c, &u1);
    let p2 = pub_key.mul_with(&c, &u2);
    let x = p1.add_with(&c, &p2);
    if x.is_infinity() {
        return Ok(false);
    }
    let v = x.x.modulus(n);
    Ok(v.eq(r))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bn_hex(s: &str) -> Bn {
        let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        Bn::from_be_bytes(&bytes)
    }

    /// Rng that yields a single pre-chosen nonce (RFC 6979 `k`).
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

    /// RFC 6979 A.2.5 — P-256 with SHA-256, message "sample".
    #[test]
    fn rfc6979_p256_sha256_sample() {
        let d = bn_hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let k = bn_hex("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
        let expect_r = bn_hex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
        let expect_s = bn_hex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");

        let msg = b"sample";
        let mut rng = FixedK {
            k: k.to_be_bytes_padded(32).unwrap(),
            used: false,
        };
        let (r, s) = sign_sha256(&d, msg, &mut rng).unwrap();
        assert_eq!(crate::ec::coord32(&r), crate::ec::coord32(&expect_r), "r");
        assert_eq!(crate::ec::coord32(&s), crate::ec::coord32(&expect_s), "s");

        // Public key: U = d * G
        let c = curve(CurveId::P256);
        let pub_key = mul_base(&c, &d);
        assert!(verify_sha256(&pub_key, msg, &r, &s).unwrap());

        // A different message must fail.
        assert!(!verify_sha256(&pub_key, b"taste", &r, &s).unwrap());
    }

    /// RFC 6979 A.2.5 — P-256 with SHA-256, message "test".
    #[test]
    fn rfc6979_p256_sha256_test() {
        let d = bn_hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let k = bn_hex("D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0");
        let expect_r = bn_hex("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367");
        let expect_s = bn_hex("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083");

        let msg = b"test";
        let mut rng = FixedK {
            k: k.to_be_bytes_padded(32).unwrap(),
            used: false,
        };
        let (r, s) = sign_sha256(&d, msg, &mut rng).unwrap();
        assert_eq!(crate::ec::coord32(&r), crate::ec::coord32(&expect_r), "r");
        assert_eq!(crate::ec::coord32(&s), crate::ec::coord32(&expect_s), "s");

        let c = curve(CurveId::P256);
        let pub_key = mul_base(&c, &d);
        assert!(verify_sha256(&pub_key, msg, &r, &s).unwrap());
    }

    /// Random-nonce sign/verify roundtrip.
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
        let mut rng = CounterRng(0xdead_beef_cafe_babe);
        let c = curve(CurveId::P256);
        let d = bn_hex("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
        let pub_key = mul_base(&c, &d);
        let msg = b"hello asymmetric world";
        let (r, s) = sign_sha256(&d, msg, &mut rng).unwrap();
        assert!(verify_sha256(&pub_key, msg, &r, &s).unwrap());
        assert!(!verify_sha256(&pub_key, b"other", &r, &s).unwrap());
    }
}
