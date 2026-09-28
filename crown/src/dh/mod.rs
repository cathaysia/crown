//! Finite-field Diffie-Hellman (RFC 3526 MODP groups).
//!
//! Only MODP 2048 for now. `generate`/`agree` reject public values
//! `y <= 1` and `y >= p - 1` per RFC 2631 / NIST SP 800-56A.

use crate::bn::Bn;
use crate::error::{CryptoError, CryptoResult};
use crate::rsa::Rng;

/// RFC 3526 §3 — 2048-bit MODP Group. Returns `(p, g)` with `g = 2`.
pub fn modp2048() -> (Bn, Bn) {
    let p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    let p = bn_hex(p_hex);
    let g = Bn::from_u64(2);
    (p, g)
}

fn bn_hex(s: &str) -> Bn {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    assert!(s.len() % 2 == 0, "odd hex length");
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
    let bytes = (p.bit_len() + 7) / 8;
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
    let mut v = Vec::with_capacity(n);
    v.resize(n, 0);
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
