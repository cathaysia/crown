//! ECDSA over P-256 / P-384 / P-521 (FIPS 186-4 / RFC 6979 compatible).
//!
//! Signature is `(r, s)` with `s` low-s not enforced (raw ECDSA as in
//! FIPS 186-4). Nonces come from the caller-supplied [`Rng`]; for the
//! deterministic RFC 6979 path feed it an HMAC-DRBG derived from the key.
//!
//! Digest selection follows the usual pairing: P-256/SHA-256,
//! P-384/SHA-384, P-521/SHA-512, though any of SHA-256/384/512 may be
//! used with any curve.

use crate::bn::Bn;
use crate::ec::{curve, generator, mul_base, CurveId, Point};
use crate::error::{CryptoError, CryptoResult};
use crate::hash::sha256::sum256;
use crate::hash::sha512::{sum384, sum512};
use crate::rng::Rng;

use alloc::vec;
use alloc::vec::Vec;
/// Hash algorithm used to digest the message before signing/verifying.
/// Mirrors the digest set OpenSSL's default provider registers for
/// ECDSA/DSA signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestId {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Sm3,
    Ripemd160,
}

/// Compute the digest of `msg` under `id`.
pub fn digest(id: DigestId, msg: &[u8]) -> Vec<u8> {
    match id {
        DigestId::Sha1 => crate::hash::sha1::sum(msg).to_vec(),
        DigestId::Sha224 => crate::hash::sha256::sum224(msg).to_vec(),
        DigestId::Sha256 => sum256(msg).to_vec(),
        DigestId::Sha384 => sum384(msg).to_vec(),
        DigestId::Sha512 => sum512(msg).to_vec(),
        DigestId::Sha3_224 => crate::hash::sha3::sum224(msg).to_vec(),
        DigestId::Sha3_256 => crate::hash::sha3::sum256(msg).to_vec(),
        DigestId::Sha3_384 => crate::hash::sha3::sum384(msg).to_vec(),
        DigestId::Sha3_512 => crate::hash::sha3::sum512(msg).to_vec(),
        DigestId::Sm3 => crate::hash::sm3::sum_sm3(msg).to_vec(),
        DigestId::Ripemd160 => crate::hash::ripemd160::sum_ripemd160(msg).to_vec(),
    }
}

/// FIPS 186-4 B.2: `e = leftmost min(N, outlen) bits of H(m)`, as an
/// integer, then reduced mod `n`.
fn bits2int_mod(hash: &[u8], n: &Bn) -> Bn {
    let n_bits = n.bit_len();
    let h_bits = hash.len() * 8;
    let keep = n_bits.min(h_bits);
    // Leftmost `keep` bits of the hash.
    let mut e = Bn::from_be_bytes(hash);
    if h_bits > keep {
        for _ in 0..(h_bits - keep) {
            e.shr1();
        }
    }
    e.modulus(n)
}

/// Sample `k` uniformly in `[1, n-1]`.
fn sample_k(n: &Bn, rng: &mut impl Rng) -> Bn {
    let n_bits = n.bit_len();
    let buf_len = n_bits.div_ceil(8);
    let excess_bits = buf_len * 8 - n_bits;
    let mut buf = vec![0u8; buf_len];
    for _ in 0..128 {
        rng.fill_bytes(&mut buf);
        if excess_bits > 0 {
            buf[0] &= 0xffu8 >> excess_bits;
        }
        let k = Bn::from_be_bytes(&buf);
        if !k.is_zero() && k.lt(n) {
            return k;
        }
    }
    // Astronomically unlikely; fall back to 1 rather than panic in a
    // signature path (caller can retry).
    Bn::one()
}

/// ECDSA sign with explicit curve and digest. Returns `(r, s)`.
pub fn sign(
    curve_id: CurveId,
    hash: DigestId,
    d: &Bn,
    msg: &[u8],
    rng: &mut impl Rng,
) -> CryptoResult<(Bn, Bn)> {
    let c = curve(curve_id);
    let n = &c.n;
    let d = d.modulus(n);
    if d.is_zero() {
        return Err(CryptoError::StrError("ecdsa: private key out of range"));
    }
    let h = digest(hash, msg);
    let e_bn = bits2int_mod(&h, n);

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

/// ECDSA verify with explicit curve and digest. Returns `true` iff the
/// signature is valid.
pub fn verify(
    curve_id: CurveId,
    hash: DigestId,
    pub_key: &Point,
    msg: &[u8],
    r: &Bn,
    s: &Bn,
) -> CryptoResult<bool> {
    let c = curve(curve_id);
    let n = &c.n;
    if pub_key.is_infinity() || !pub_key.is_on_curve(&c) {
        return Ok(false);
    }
    if r.is_zero() || !r.lt(n) || s.is_zero() || !s.lt(n) {
        return Ok(false);
    }
    let h = digest(hash, msg);
    let e = bits2int_mod(&h, n);

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

/// ECDSA sign over P-256 with SHA-256. Returns `(r, s)`.
pub fn sign_sha256(d: &Bn, msg: &[u8], rng: &mut impl Rng) -> CryptoResult<(Bn, Bn)> {
    sign(CurveId::P256, DigestId::Sha256, d, msg, rng)
}

/// ECDSA verify over P-256 with SHA-256. Returns `true` iff the
/// signature is valid.
pub fn verify_sha256(pub_key: &Point, msg: &[u8], r: &Bn, s: &Bn) -> CryptoResult<bool> {
    verify(CurveId::P256, DigestId::Sha256, pub_key, msg, r, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bn_hex(s: &str) -> Bn {
        let mut s: alloc::string::String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if s.len() % 2 == 1 {
            s.insert(0, '0');
        }
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        Bn::from_be_bytes(&bytes)
    }

    fn padded(b: &Bn, n: usize) -> Vec<u8> {
        crate::ec::coord_padded(b, n)
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
                let off = self.k.len().saturating_sub(out.len());
                // Right-align: sample_k buffers are order-sized, k vectors
                // may be longer (leading zero bytes) or equal length.
                if self.k.len() >= out.len() {
                    out[..n].copy_from_slice(&self.k[off..off + n]);
                } else {
                    let start = out.len() - self.k.len();
                    out[start..].copy_from_slice(&self.k);
                }
                self.used = true;
            } else {
                for b in out.iter_mut() {
                    *b = 0;
                }
            }
        }
    }

    fn fixed_k(k: &Bn, order_bytes: usize) -> FixedK {
        FixedK {
            k: padded(k, order_bytes),
            used: false,
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
        let mut rng = fixed_k(&k, 32);
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
        let mut rng = fixed_k(&k, 32);
        let (r, s) = sign_sha256(&d, msg, &mut rng).unwrap();
        assert_eq!(crate::ec::coord32(&r), crate::ec::coord32(&expect_r), "r");
        assert_eq!(crate::ec::coord32(&s), crate::ec::coord32(&expect_s), "s");

        let c = curve(CurveId::P256);
        let pub_key = mul_base(&c, &d);
        assert!(verify_sha256(&pub_key, msg, &r, &s).unwrap());
    }

    /// RFC 6979 A.2.6 — P-384 with SHA-384, message "sample".
    #[test]
    fn rfc6979_p384_sha384_sample() {
        let d = bn_hex(
            "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8
             96D5724E4C70A825F872C9EA60D2EDF5",
        );
        let k = bn_hex(
            "94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA
             2907E3E83BA95368623B8C4686915CF9",
        );
        let expect_r = bn_hex(
            "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C
             81A648152E44ACF96E36DD1E80FABE46",
        );
        let expect_s = bn_hex(
            "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F
             A329C145786E679E7B82C71A38628AC8",
        );

        let msg = b"sample";
        let mut rng = fixed_k(&k, 48);
        let (r, s) = sign(CurveId::P384, DigestId::Sha384, &d, msg, &mut rng).unwrap();
        assert_eq!(padded(&r, 48), padded(&expect_r, 48), "r");
        assert_eq!(padded(&s, 48), padded(&expect_s, 48), "s");

        let c = curve(CurveId::P384);
        let pub_key = mul_base(&c, &d);
        assert!(verify(CurveId::P384, DigestId::Sha384, &pub_key, msg, &r, &s).unwrap());
        assert!(!verify(CurveId::P384, DigestId::Sha384, &pub_key, b"taste", &r, &s).unwrap());
    }

    /// RFC 6979 A.2.6 — P-384 with SHA-384, message "test".
    #[test]
    fn rfc6979_p384_sha384_test() {
        let d = bn_hex(
            "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8
             96D5724E4C70A825F872C9EA60D2EDF5",
        );
        let k = bn_hex(
            "015EE46A5BF88773ED9123A5AB0807962D193719503C527B031B4C2D225092AD
             A71F4A459BC0DA98ADB95837DB8312EA",
        );
        let expect_r = bn_hex(
            "8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB
             0542A7F0812998DA8F1DD3CA3CF023DB",
        );
        let expect_s = bn_hex(
            "DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E0
             6A739F040649A667BF3B828246BAA5A5",
        );

        let msg = b"test";
        let mut rng = fixed_k(&k, 48);
        let (r, s) = sign(CurveId::P384, DigestId::Sha384, &d, msg, &mut rng).unwrap();
        assert_eq!(padded(&r, 48), padded(&expect_r, 48), "r");
        assert_eq!(padded(&s, 48), padded(&expect_s, 48), "s");

        let c = curve(CurveId::P384);
        let pub_key = mul_base(&c, &d);
        assert!(verify(CurveId::P384, DigestId::Sha384, &pub_key, msg, &r, &s).unwrap());
    }

    /// RFC 6979 A.2.7 — P-521 with SHA-512, message "sample".
    #[test]
    fn rfc6979_p521_sha512_sample() {
        let d = bn_hex(
            "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C
             AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83
             538",
        );
        let k = bn_hex(
            "1DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F1019
             8B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBF
             FD3",
        );
        let expect_r = bn_hex(
            "0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F1
             74E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E37
             7FA",
        );
        let expect_s = bn_hex(
            "0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF2
             82623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A
             67A",
        );

        let msg = b"sample";
        let mut rng = fixed_k(&k, 66);
        let (r, s) = sign(CurveId::P521, DigestId::Sha512, &d, msg, &mut rng).unwrap();
        assert_eq!(padded(&r, 66), padded(&expect_r, 66), "r");
        assert_eq!(padded(&s, 66), padded(&expect_s, 66), "s");

        let c = curve(CurveId::P521);
        let pub_key = mul_base(&c, &d);
        assert!(verify(CurveId::P521, DigestId::Sha512, &pub_key, msg, &r, &s).unwrap());
        assert!(!verify(CurveId::P521, DigestId::Sha512, &pub_key, b"taste", &r, &s).unwrap());
    }

    /// Random-nonce sign/verify roundtrip on every curve.
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
        let cases = [
            (CurveId::P256, DigestId::Sha256),
            (CurveId::P384, DigestId::Sha384),
            (CurveId::P521, DigestId::Sha512),
        ];
        for (cid, did) in cases {
            let c = curve(cid);
            let d = bn_hex("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
            let pub_key = mul_base(&c, &d);
            let msg = b"hello asymmetric world";
            let (r, s) = sign(cid, did, &d, msg, &mut rng).unwrap();
            assert!(verify(cid, did, &pub_key, msg, &r, &s).unwrap());
            assert!(!verify(cid, did, &pub_key, b"other", &r, &s).unwrap());
        }
    }
}
