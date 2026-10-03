//! Finite-field Diffie-Hellman (RFC 3526 MODP and RFC 7919 ffdhe groups).
//!
//! `generate`/`agree` reject public values `y <= 1` and `y >= p - 1` per
//! RFC 2631 / NIST SP 800-56A.

use crate::bn::Bn;
use crate::error::{CryptoError, CryptoResult};
use alloc::vec;

use crate::rng::Rng;

use alloc::string::String;
use alloc::vec::Vec;
/// RFC 3526 §3 — 2048-bit MODP Group. Returns `(p, g)` with `g = 2`.
pub fn modp2048() -> (Bn, Bn) {
    let p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    let p = bn_hex(p_hex);
    let g = Bn::from_u64(2);
    (p, g)
}

/// RFC 7919 ffdhe groups (2048..=8192 bits). Returns `(p, g)` with `g = 2`,
/// or `None` for unsupported sizes.
pub fn ffdhe(bits: usize) -> Option<(Bn, Bn)> {
    const TABLE: &[(usize, &str)] = &[
        (
            2048,
            concat!(
                "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695",
                "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a",
                "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935",
                "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a",
                "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4",
                "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61",
                "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005",
                "c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff"
            ),
        ),
        (
            3072,
            concat!(
                "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695",
                "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a",
                "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935",
                "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a",
                "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4",
                "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61",
                "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005",
                "c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035b",
                "bc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c",
                "aefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff",
                "5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e",
                "0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b66c62e37ffffffffffffffff"
            ),
        ),
        (
            4096,
            concat!(
                "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695",
                "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a",
                "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935",
                "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a",
                "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4",
                "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61",
                "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005",
                "c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035b",
                "bc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c",
                "aefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff",
                "5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e",
                "0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb",
                "7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a",
                "7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038",
                "092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf",
                "8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e655f6affffffffffffffff"
            ),
        ),
        (
            6144,
            concat!(
                "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695",
                "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a",
                "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935",
                "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a",
                "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4",
                "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61",
                "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005",
                "c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035b",
                "bc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c",
                "aefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff",
                "5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e",
                "0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb",
                "7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a",
                "7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038",
                "092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf",
                "8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e0dd9020bfd64b645036c7a",
                "4e677d2c38532a3a23ba4442caf53ea63bb454329b7624c8917bdd64b1c0fd4c",
                "b38e8c334c701c3acdad0657fccfec719b1f5c3e4e46041f388147fb4cfdb477",
                "a52471f7a9a96910b855322edb6340d8a00ef092350511e30abec1fff9e3a26e",
                "7fb29f8c183023c3587e38da0077d9b4763e4e4b94b2bbc194c6651e77caf992",
                "eeaac0232a281bf6b3a739c1226116820ae8db5847a67cbef9c9091b462d538c",
                "d72b03746ae77f5e62292c311562a846505dc82db854338ae49f5235c95b9117",
                "8ccf2dd5cacef403ec9d1810c6272b045b3b71f9dc6b80d63fdd4a8e9adb1e69",
                "62a69526d43161c1a41d570d7938dad4a40e329cd0e40e65ffffffffffffffff"
            ),
        ),
        (
            8192,
            concat!(
                "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695",
                "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a",
                "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935",
                "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a",
                "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4",
                "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61",
                "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005",
                "c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035b",
                "bc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c",
                "aefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff",
                "5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e",
                "0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb",
                "7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a",
                "7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038",
                "092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf",
                "8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e0dd9020bfd64b645036c7a",
                "4e677d2c38532a3a23ba4442caf53ea63bb454329b7624c8917bdd64b1c0fd4c",
                "b38e8c334c701c3acdad0657fccfec719b1f5c3e4e46041f388147fb4cfdb477",
                "a52471f7a9a96910b855322edb6340d8a00ef092350511e30abec1fff9e3a26e",
                "7fb29f8c183023c3587e38da0077d9b4763e4e4b94b2bbc194c6651e77caf992",
                "eeaac0232a281bf6b3a739c1226116820ae8db5847a67cbef9c9091b462d538c",
                "d72b03746ae77f5e62292c311562a846505dc82db854338ae49f5235c95b9117",
                "8ccf2dd5cacef403ec9d1810c6272b045b3b71f9dc6b80d63fdd4a8e9adb1e69",
                "62a69526d43161c1a41d570d7938dad4a40e329ccff46aaa36ad004cf600c838",
                "1e425a31d951ae64fdb23fcec9509d43687feb69edd1cc5e0b8cc3bdf64b10ef",
                "86b63142a3ab8829555b2f747c932665cb2c0f1cc01bd70229388839d2af05e4",
                "54504ac78b7582822846c0ba35c35f5c59160cc046fd8251541fc68c9c86b022",
                "bb7099876a460e7451a8a93109703fee1c217e6c3826e52c51aa691e0e423cfc",
                "99e9e31650c1217b624816cdad9a95f9d5b8019488d9c0a0a1fe3075a577e231",
                "83f81d4a3f2fa4571efc8ce0ba8a4fe8b6855dfe72b0a66eded2fbabfbe58a30",
                "fafabe1c5d71a87e2f741ef8c1fe86fea6bbfde530677f0d97d11d49f7a8443d",
                "0822e506a9f4614e011e2a94838ff88cd68c8bb7c5c6424cffffffffffffffff"
            ),
        ),
    ];
    let (_, p_hex) = TABLE.iter().copied().find(|(l, _)| *l == bits)?;
    Some((bn_hex(p_hex), Bn::from_u64(2)))
}

fn bn_hex(s: &str) -> Bn {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    assert!(s.len().is_multiple_of(2), "odd hex length");
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    Bn::from_be_bytes(&bytes)
}

/// Reject `y <= 1` or `y >= p - 1` (small-subgroup / trivial values).
fn check_public(y: &Bn, p: &Bn) -> CryptoResult<()> {
    if y.is_zero() || y.is_one() {
        return Err(CryptoError::StrError("dh: public value too small"));
    }
    let one = Bn::one();
    let pm1 = p.sub(&one)?;
    if !y.lt(&pm1) {
        return Err(CryptoError::StrError("dh: public value too large"));
    }
    Ok(())
}

/// Generate a DH key pair `(x, y)` with `y = g^x mod p`.
///
/// Private `x` is drawn uniformly from `[2, p-2]`.
pub fn generate(p: &Bn, g: &Bn, rng: &mut impl Rng) -> CryptoResult<(Bn, Bn)> {
    if !p.is_odd() || p.bit_len() < 2 {
        return Err(CryptoError::StrError("dh: invalid modulus"));
    }
    if g.is_zero() || g.is_one() {
        return Err(CryptoError::StrError("dh: invalid generator"));
    }
    let one = Bn::one();
    let pm2 = p.sub(&one)?.sub(&one)?;
    let bytes = p.bit_len().div_ceil(8);
    let mut buf = alloc_zeroes(bytes);
    let mut x = Bn::zero();
    for _ in 0..256 {
        rng.fill_bytes(&mut buf);
        x = Bn::from_be_bytes(&buf);
        // Keep x in [2, p-2].
        if x.bit_len() >= 2 && x.lt(&pm2) && !x.is_zero() && !x.is_one() {
            break;
        }
    }
    if x.is_zero() || x.is_one() || !x.lt(&pm2) {
        return Err(CryptoError::StrError("dh: failed to sample private key"));
    }
    let y = g.mod_pow_odd_consttime(&x, p)?;
    check_public(&y, p)?;
    Ok((x, y))
}

/// Compute the shared secret `peer^x mod p`.
pub fn agree(p: &Bn, private: &Bn, peer: &Bn) -> CryptoResult<Bn> {
    if !p.is_odd() {
        return Err(CryptoError::StrError("dh: invalid modulus"));
    }
    check_public(peer, p)?;
    let one = Bn::one();
    let pm2 = p.sub(&one)?.sub(&one)?;
    let x = private.modulus(&pm2.add(&one)); // reduce into [0, p-2] loosely
    if x.is_zero() || x.is_one() {
        return Err(CryptoError::StrError("dh: private key out of range"));
    }
    let s = peer.mod_pow_odd_consttime(&x, p)?;
    check_public(&s, p)?;
    Ok(s)
}

fn alloc_zeroes(n: usize) -> Vec<u8> {
    let v = vec![0; n];
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CounterRng(u64);
    impl Rng for CounterRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (self.0 >> 33) as u8;
            }
        }
    }

    #[test]
    fn ffdhe_groups() {
        for bits in [2048usize, 3072, 4096, 6144, 8192] {
            let (p, g) = ffdhe(bits).unwrap();
            assert_eq!(p.bit_len(), bits, "ffdhe{bits} p size");
            assert!(p.is_odd());
            assert_eq!(g, Bn::from_u64(2));
            assert!(ffdhe(bits - 1).is_none() || bits == 2048);
        }
        assert!(ffdhe(1024).is_none());
    }

    // The leading and trailing 128 bytes of the RFC 7919 ffdhe2048
    // prime (cross-checked against OpenSSL's `group:ffdhe2048` output).
    #[test]
    fn ffdhe2048_known_value() {
        let (p, _g) = ffdhe(2048).unwrap();
        let head = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A";
        let tail = "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF";
        let bytes = p.to_be_bytes();
        assert_eq!(bytes.len(), 256);
        let head_b: Vec<u8> = (0..head.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&head[i..i + 2], 16).unwrap())
            .collect();
        let tail_b: Vec<u8> = (0..tail.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&tail[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(&bytes[..head_b.len()], &head_b[..]);
        assert_eq!(&bytes[bytes.len() - tail_b.len()..], &tail_b[..]);
    }

    #[test]
    fn ffdhe_generate_agree_roundtrip() {
        let (p, g) = ffdhe(2048).unwrap();
        let mut rng = CounterRng(0xfeed_face_dead_beef);
        let (x1, y1) = generate(&p, &g, &mut rng).unwrap();
        let (x2, y2) = generate(&p, &g, &mut rng).unwrap();
        assert_eq!(agree(&p, &x1, &y2).unwrap(), agree(&p, &x2, &y1).unwrap());
    }

    #[test]
    fn modp2048_params() {
        let (p, g) = modp2048();
        assert_eq!(p.bit_len(), 2048);
        assert!(p.is_odd());
        assert!(g.is_one() || g == Bn::from_u64(2));
        // p ≡ 7 (mod 8) for RFC 3526 MODP 2048
        let pmod8 = p.modulus(&Bn::from_u64(8));
        assert_eq!(pmod8, Bn::from_u64(7));
    }

    #[test]
    fn generate_agree_roundtrip() {
        let (p, g) = modp2048();
        let mut rng = CounterRng(0x0123_4567_89ab_cdef);
        let (x1, y1) = generate(&p, &g, &mut rng).unwrap();
        let (x2, y2) = generate(&p, &g, &mut rng).unwrap();
        let s1 = agree(&p, &x1, &y2).unwrap();
        let s2 = agree(&p, &x2, &y1).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn rejects_trivial_publics() {
        let (p, g) = modp2048();
        let mut rng = CounterRng(1);
        let (x, _y) = generate(&p, &g, &mut rng).unwrap();
        assert!(agree(&p, &x, &Bn::zero()).is_err());
        assert!(agree(&p, &x, &Bn::one()).is_err());
        let pm1 = p.sub(&Bn::one()).unwrap();
        assert!(agree(&p, &x, &pm1).is_err());
    }
}
