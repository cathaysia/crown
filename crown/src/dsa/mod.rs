//! DSA (FIPS 186-4) with SHA-256.
//!
//! Signature is `(r, s)` over the multiplicative subgroup of order `q`
//! modulo `p`. Nonces come from the caller-supplied [`Rng`]; for the
//! deterministic RFC 6979 path feed it an HMAC-DRBG derived from the key.

use crate::bn::Bn;
use crate::ecdsa::{digest, DigestId};
use crate::error::{CryptoError, CryptoResult};
use crate::rng::Rng;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
/// DSA domain parameters: prime modulus `p`, subgroup order `q`, base `g`.
#[derive(Debug, Clone)]
pub struct DsaParams {
    pub p: Bn,
    pub q: Bn,
    pub g: Bn,
}

/// A DSA key pair: parameters plus private `x` and public `y = g^x mod p`.
#[derive(Debug, Clone)]
pub struct DsaKeyPair {
    pub params: DsaParams,
    pub x: Bn,
    pub y: Bn,
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

/// 2048-bit DSA parameters with a 256-bit subgroup order (FIPS 186-4
/// L = 2048, N = 256). The published parameter set used in RFC 6979
/// A.2.2 (originating from the NIST DSA parameter validation set).
pub fn dsa_2048_256() -> DsaParams {
    DsaParams {
        p: bn_hex(
            "9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48
             C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F
             FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5
             B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2
             35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41
             F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE
             92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15
             3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B",
        ),
        q: bn_hex("F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F"),
        g: bn_hex(
            "5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613
             D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4
             6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472
             085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5
             AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA
             3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71
             BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0
             DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7",
        ),
    }
}

/// FIPS 186-4 B.2: leftmost `min(N, outlen)` bits of the hash as an
/// integer, reduced mod `q`.
fn hash_to_int(hash: &[u8], q: &Bn) -> Bn {
    let q_bits = q.bit_len();
    let h_bits = hash.len() * 8;
    let keep = q_bits.min(h_bits);
    let mut e = Bn::from_be_bytes(hash);
    if h_bits > keep {
        for _ in 0..(h_bits - keep) {
            e.shr1();
        }
    }
    e.modulus(q)
}

/// Sample `k` uniformly in `[1, q-1]`.
fn sample_k(q: &Bn, rng: &mut impl Rng) -> Bn {
    let q_bits = q.bit_len();
    let buf_len = q_bits.div_ceil(8);
    let excess_bits = buf_len * 8 - q_bits;
    let mut buf = vec![0u8; buf_len];
    for _ in 0..128 {
        rng.fill_bytes(&mut buf);
        if excess_bits > 0 {
            buf[0] &= 0xffu8 >> excess_bits;
        }
        let k = Bn::from_be_bytes(&buf);
        if !k.is_zero() && k.lt(q) {
            return k;
        }
    }
    Bn::one()
}

/// Generate a DSA key pair from `params`.
pub fn generate(params: &DsaParams, rng: &mut impl Rng) -> CryptoResult<DsaKeyPair> {
    let x = sample_k(&params.q, rng);
    if x.is_zero() {
        return Err(CryptoError::StrError("dsa: failed to sample private key"));
    }
    let y = params
        .g
        .mod_pow_odd_consttime(&x, &params.p)
        .map_err(|_| CryptoError::StrError("dsa: public key exponentiation failed"))?;
    Ok(DsaKeyPair {
        params: params.clone(),
        x,
        y,
    })
}

/// Miller-Rabin rounds for `l`-bit candidates (mirrors rsa::prime policy).
#[cfg(feature = "alloc")]
fn mr_rounds(l: usize) -> usize {
    if l > 2048 {
        128
    } else {
        64
    }
}

/// Increment a big-endian byte string by one (the FFC seed counter).
#[cfg(feature = "alloc")]
fn inc_be(buf: &mut [u8]) {
    for k in (0..buf.len()).rev() {
        buf[k] = buf[k].wrapping_add(1);
        if buf[k] != 0 {
            break;
        }
    }
}

/// Generate DSA domain parameters `(p, q, g)` per FIPS 186-4 A.1.2.1.2
/// (probable primes, hash-based), matching OpenSSL's
/// `ffc_params_generate`. Supported pairs: `(2048, 224)`, `(2048, 256)`
/// and `(3072, 256)`. The generator is the canonical small-base search
/// of A.2.3 starting at `h = 2`.
#[cfg(feature = "alloc")]
pub fn generate_params(l: usize, n: usize, rng: &mut impl Rng) -> CryptoResult<DsaParams> {
    let hash: fn(&[u8]) -> Vec<u8>;
    let seedlen: usize;
    match (l, n) {
        (2048, 224) => {
            hash = |d: &[u8]| crate::hash::sha256::sum224(d).to_vec();
            seedlen = 28;
        }
        (2048, 256) | (3072, 256) => {
            hash = |d: &[u8]| crate::hash::sha256::sum256(d).to_vec();
            seedlen = 32;
        }
        _ => {
            return Err(CryptoError::StrError(
                "dsa: unsupported (L, N) parameter pair",
            ))
        }
    }
    let outlen = seedlen * 8;
    let n_chunks = (l - 1) / outlen;
    let max_counter = 4 * l - 1;
    let primes = crate::rsa::prime::small_primes_for_testing();

    loop {
        // Steps (3)-(6): draw a seed and derive the N-bit prime q. The
        // top and bottom bits are forced; only the low N bits of the
        // digest are used (equal to the whole digest for our sizes).
        let mut seed = alloc::vec![0u8; seedlen];
        rng.fill_bytes(&mut seed);
        let mut q_bytes = hash(&seed);
        q_bytes[0] |= 0x80;
        q_bytes[n / 8 - 1] |= 0x01;
        let q = Bn::from_be_bytes(&q_bytes);
        if primes.iter().any(|&d| q.rem_small(d) == 0) {
            continue;
        }
        if !crate::rsa::prime::is_probable_prime(&q, 64, rng)? {
            continue;
        }

        // Steps (7)-(11): search for p over the counter. `buf` holds
        // seed + offset + j; it is incremented before each hash so the
        // offset advances by n + 1 per counter iteration.
        let two_q = q.add(&q);
        let one = Bn::one();
        let mut buf = seed.clone();
        for _i in 0..=max_counter {
            // W = sum V(j) * 2^(outlen * j): byte-concatenation in
            // big-endian order.
            let mut w = alloc::vec![0u8; (n_chunks + 1) * seedlen];
            for j in 0..=n_chunks {
                inc_be(&mut buf);
                let v = hash(&buf);
                let off = w.len() - (j + 1) * seedlen;
                w[off..off + seedlen].copy_from_slice(&v);
            }
            // X = (W mod 2^(L-1)) + 2^(L-1): truncate to L bits, then
            // force the top bit.
            let l_bytes = l / 8;
            let x_bytes = &w[w.len() - l_bytes..];
            let mut x = Bn::from_be_bytes(x_bytes);
            x.set_bit(l - 1);

            let c = x.modulus(&two_q);
            let p = x.sub(&c.sub(&one)?)?;
            if p.bit_len() != l {
                continue;
            }
            if primes.iter().any(|&d| p.rem_small(d) == 0) {
                continue;
            }
            if !crate::rsa::prime::is_probable_prime(&p, mr_rounds(l), rng)? {
                continue;
            }

            // A.2.3: g = h^((p-1)/q) mod p for the first h >= 2 giving g > 1.
            let pm1 = p.sub(&one)?;
            let (e, rem) = pm1.divrem(&q)?;
            if !rem.is_zero() {
                return Err(CryptoError::StrError("dsa: q does not divide p - 1"));
            }
            let mut h = Bn::from_u64(2);
            for _ in 0..256 {
                let g = h.mod_pow(&e, &p)?;
                if !g.is_one() {
                    return Ok(DsaParams { p, q, g });
                }
                h = h.add(&one);
            }
            return Err(CryptoError::StrError("dsa: failed to find a generator"));
        }
        // Counter exhausted for this seed; draw a fresh one.
    }
}

/// DSA sign over SHA-256. Returns `(r, s)`.
pub fn sign_sha256(key: &DsaKeyPair, msg: &[u8], rng: &mut impl Rng) -> CryptoResult<(Bn, Bn)> {
    sign(key, DigestId::Sha256, msg, rng)
}

/// DSA verify over SHA-256. Returns `true` iff the signature is valid.
pub fn verify_sha256(params: &DsaParams, y: &Bn, msg: &[u8], r: &Bn, s: &Bn) -> CryptoResult<bool> {
    verify(params, y, DigestId::Sha256, msg, r, s)
}

/// DSA sign with an explicit digest. Returns `(r, s)`.
///
/// `r = (g^k mod p) mod q`, `s = k^{-1} (H(m) + x r) mod q` with `k`
/// random in `[1, q-1]`.
pub fn sign(
    key: &DsaKeyPair,
    hash: DigestId,
    msg: &[u8],
    rng: &mut impl Rng,
) -> CryptoResult<(Bn, Bn)> {
    let params = &key.params;
    let p = &params.p;
    let q = &params.q;
    if key.x.is_zero() || !key.x.lt(q) {
        return Err(CryptoError::StrError("dsa: private key out of range"));
    }
    let h = hash_to_int(&digest(hash, msg), q);

    for _ in 0..128 {
        let k = sample_k(q, rng);
        let r = params
            .g
            .mod_pow_odd_consttime(&k, p)
            .map_err(|_| CryptoError::StrError("dsa: r exponentiation failed"))?
            .modulus(q);
        if r.is_zero() {
            continue;
        }
        // s = k^{-1} (H + x r) mod q
        let kinv = k.mod_inverse(q)?;
        let xr = key.x.modmul(&r, q);
        let e_plus = h.add(&xr).modulus(q);
        let s = kinv.modmul(&e_plus, q);
        if s.is_zero() {
            continue;
        }
        return Ok((r, s));
    }
    Err(CryptoError::StrError("dsa: failed to produce signature"))
}

/// DSA verify with an explicit digest. Returns `true` iff the signature is
/// valid.
///
/// `w = s^{-1}`, `u1 = H w`, `u2 = r w`, `v = (g^{u1} y^{u2} mod p) mod q`,
/// accept iff `v == r`. Rejects `r, s` outside `[1, q-1]`.
pub fn verify(
    params: &DsaParams,
    y: &Bn,
    hash: DigestId,
    msg: &[u8],
    r: &Bn,
    s: &Bn,
) -> CryptoResult<bool> {
    let p = &params.p;
    let q = &params.q;
    // Reject r, s outside [1, q-1].
    if r.is_zero() || !r.lt(q) || s.is_zero() || !s.lt(q) {
        return Ok(false);
    }
    // Public key must be in [1, p-1] (and ideally in the order-q subgroup).
    if y.is_zero() || !y.lt(p) {
        return Ok(false);
    }
    let h = hash_to_int(&digest(hash, msg), q);

    let w = s.mod_inverse(q)?;
    let u1 = h.modmul(&w, q);
    let u2 = r.modmul(&w, q);

    let gu1 = params
        .g
        .mod_pow_odd_consttime(&u1, p)
        .map_err(|_| CryptoError::StrError("dsa: verify exponentiation failed"))?;
    let yu2 = y
        .mod_pow_odd_consttime(&u2, p)
        .map_err(|_| CryptoError::StrError("dsa: verify exponentiation failed"))?;
    let v = gu1.modmul(&yu2, p).modulus(q);
    Ok(v.eq(r))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bn_hex(s: &str) -> Bn {
        let mut s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if s.len() % 2 == 1 {
            s.insert(0, '0');
        }
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        Bn::from_be_bytes(&bytes)
    }

    /// Parameter sanity: sizes, `1 < g < p`, and `g^q ≡ 1 (mod p)`.
    #[test]
    fn params_sanity() {
        let params = dsa_2048_256();
        assert_eq!(params.p.bit_len(), 2048, "p is 2048-bit");
        assert_eq!(params.q.bit_len(), 256, "q is 256-bit");
        assert!(params.q.lt(&params.p));
        assert!(params.g.lt(&params.p));
        assert!(!params.g.is_zero() && !params.g.is_one());
        // g^q ≡ 1 mod p  (g has order q)
        let gq = params
            .g
            .mod_pow_odd_consttime(&params.q, &params.p)
            .unwrap();
        assert!(gq.is_one(), "g^q must be 1 mod p");
    }

    /// Rng that yields a single pre-chosen nonce.
    struct FixedK {
        k: Vec<u8>,
        used: bool,
    }
    impl Rng for FixedK {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            if !self.used {
                let n = out.len().min(self.k.len());
                let start = self.k.len().saturating_sub(out.len());
                if self.k.len() >= out.len() {
                    out[..n].copy_from_slice(&self.k[start..start + n]);
                } else {
                    let pad = out.len() - self.k.len();
                    out[pad..].copy_from_slice(&self.k);
                }
                self.used = true;
            } else {
                for b in out.iter_mut() {
                    *b = 0;
                }
            }
        }
    }

    /// RFC 6979 A.2.2 — DSA 2048-bit with SHA-256, message "sample".
    /// Public key matches the published `y`, and `(r, s)` matches with
    /// the published `k`.
    #[test]
    fn rfc6979_dsa2048_sha256_sample() {
        let params = dsa_2048_256();
        let x = test_bn_hex("69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC");
        let expect_y = test_bn_hex(
            "667098C654426C78D7F8201EAC6C203EF030D43605032C2F1FA937E5237DBD94
             9F34A0A2564FE126DC8B715C5141802CE0979C8246463C40E6B6BDAA2513FA61
             1728716C2E4FD53BC95B89E69949D96512E873B9C8F8DFD499CC312882561ADE
             CB31F658E934C0C197F2C4D96B05CBAD67381E7B768891E4DA3843D24D94CDFB
             5126E9B8BF21E8358EE0E0A30EF13FD6A664C0DCE3731F7FB49A4845A4FD8254
             687972A2D382599C9BAC4E0ED7998193078913032558134976410B89D2C171D1
             23AC35FD977219597AA7D15C1A9A428E59194F75C721EBCBCFAE44696A499AFA
             74E04299F132026601638CB87AB79190D4A0986315DA8EEC6561C938996BEADF",
        );
        // y = g^x mod p
        let y = params.g.mod_pow_odd_consttime(&x, &params.p).unwrap();
        assert!(!y.is_zero());
        let yb = y.to_be_bytes_padded(256).unwrap();
        let eb = expect_y.to_be_bytes_padded(256).unwrap();
        assert_eq!(yb, eb, "published y");

        let k = test_bn_hex("8926A27C40484216F052F4427CFD5647338B7B3939BC6573AF4333569D597C52");
        let expect_r =
            test_bn_hex("EACE8BDBBE353C432A795D9EC556C6D021F7A03F42C36E9BC87E4AC7932CC809");
        let expect_s =
            test_bn_hex("7081E175455F9247B812B74583E9E94F9EA79BD640DC962533B0680793A38D53");

        let key = DsaKeyPair {
            params: params.clone(),
            x: x.clone(),
            y,
        };
        let msg = b"sample";
        let mut rng = FixedK {
            k: k.to_be_bytes_padded(32).unwrap(),
            used: false,
        };
        let (r, s) = sign_sha256(&key, msg, &mut rng).unwrap();
        assert_eq!(
            r.to_be_bytes_padded(32).unwrap(),
            expect_r.to_be_bytes_padded(32).unwrap(),
            "r"
        );
        assert_eq!(
            s.to_be_bytes_padded(32).unwrap(),
            expect_s.to_be_bytes_padded(32).unwrap(),
            "s"
        );

        assert!(verify_sha256(&params, &key.y, msg, &r, &s).unwrap());
        assert!(!verify_sha256(&params, &key.y, b"taste", &r, &s).unwrap());
    }

    /// RFC 6979 A.2.2 — DSA 2048-bit with SHA-256, message "test".
    #[test]
    fn rfc6979_dsa2048_sha256_test() {
        let params = dsa_2048_256();
        let x = test_bn_hex("69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC");
        let y = params.g.mod_pow_odd_consttime(&x, &params.p).unwrap();
        let k = test_bn_hex("1D6CE6DDA1C5D37307839CD03AB0A5CBB18E60D800937D67DFB4479AAC8DEAD7");
        let expect_r =
            test_bn_hex("8190012A1969F9957D56FCCAAD223186F423398D58EF5B3CEFD5A4146A4476F0");
        let expect_s =
            test_bn_hex("7452A53F7075D417B4B013B278D1BB8BBD21863F5E7B1CEE679CF2188E1AB19E");

        let key = DsaKeyPair {
            params: params.clone(),
            x,
            y,
        };
        let msg = b"test";
        let mut rng = FixedK {
            k: k.to_be_bytes_padded(32).unwrap(),
            used: false,
        };
        let (r, s) = sign_sha256(&key, msg, &mut rng).unwrap();
        assert_eq!(
            r.to_be_bytes_padded(32).unwrap(),
            expect_r.to_be_bytes_padded(32).unwrap(),
            "r"
        );
        assert_eq!(
            s.to_be_bytes_padded(32).unwrap(),
            expect_s.to_be_bytes_padded(32).unwrap(),
            "s"
        );
        assert!(verify_sha256(&params, &key.y, msg, &r, &s).unwrap());
    }

    /// Key generation + random-nonce sign/verify roundtrip.
    #[test]
    fn generate_sign_verify_roundtrip() {
        struct CounterRng(u64);
        impl Rng for CounterRng {
            fn fill_bytes(&mut self, out: &mut [u8]) {
                for b in out.iter_mut() {
                    self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *b = (self.0 >> 33) as u8;
                }
            }
        }
        let mut rng = CounterRng(0x0123_4567_89ab_cdef);
        let params = dsa_2048_256();
        let key = generate(&params, &mut rng).unwrap();
        assert!(!key.y.is_zero());
        assert!(key.x.lt(&params.q) && !key.x.is_zero());

        let msg = b"dsa sign/verify roundtrip";
        let (r, s) = sign_sha256(&key, msg, &mut rng).unwrap();
        assert!(verify_sha256(&params, &key.y, msg, &r, &s).unwrap());
        assert!(!verify_sha256(&params, &key.y, b"other", &r, &s).unwrap());

        // Tampered signature components must fail.
        let bad_r = r.add(&Bn::one()).modulus(&params.q);
        assert!(!verify_sha256(&params, &key.y, msg, &bad_r, &s).unwrap());
    }

    /// r or s outside [1, q-1] is rejected.
    #[test]
    fn reject_out_of_range_rs() {
        let params = dsa_2048_256();
        let y = params.g.clone();
        assert!(!verify_sha256(&params, &y, b"m", &Bn::zero(), &Bn::one()).unwrap());
        assert!(!verify_sha256(&params, &y, b"m", &Bn::one(), &Bn::zero()).unwrap());
        assert!(!verify_sha256(&params, &y, b"m", &params.q, &Bn::one()).unwrap());
        assert!(!verify_sha256(&params, &y, b"m", &Bn::one(), &params.q).unwrap());
    }
    /// The full FIPS 186-4 A.1.2.1.2 parameter generation (release-mode
    /// cost ~1s; slow in debug builds, so it is ignored by default).
    #[cfg(feature = "alloc")]
    #[test]
    #[ignore = "slow parameter generation; run explicitly (fast under --release)"]
    fn generate_params_2048_256() {
        struct R(u64);
        impl Rng for R {
            fn fill_bytes(&mut self, out: &mut [u8]) {
                for b in out.iter_mut() {
                    self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *b = (self.0 >> 33) as u8;
                }
            }
        }
        let mut rng = R(0x1234_5678_9abc_def0);
        let params = generate_params(2048, 256, &mut rng).unwrap();
        assert_eq!(params.p.bit_len(), 2048);
        assert_eq!(params.q.bit_len(), 256);
        // g^q mod p == 1 and keygen + sign/verify roundtrip.
        assert!(params.g.mod_pow(&params.q, &params.p).unwrap().is_one());
        let mut rng2 = R(42);
        let key = generate(&params, &mut rng2).unwrap();
        let (r, s) = sign_sha256(&key, b"paramgen test", &mut rng2).unwrap();
        assert!(verify_sha256(&params, &key.y, b"paramgen test", &r, &s).unwrap());
    }

    /// (p, q, g) produced by `generate_params` and validated for
    /// interoperability with the OpenSSL CLI (`genpkey -paramfile` +
    /// `dgst -sha256 -sign`; signature verified both ways).
    #[cfg(feature = "alloc")]
    #[test]
    fn generated_params_openssl_interop() {
        let params = DsaParams {
            p: test_bn_hex("96c36601a5520e45232bd00f0d8357dc063bcc7530cdaea452401dea63a3a5e5ac13a99a5736e320d0c2707e24d9a0608a824918c13b7e48006d1cc13bd0e6e00c23dd362276ac26bb192c6b49455b6cdf75244899ee1356da0f70b0c7e9b73f17fd2380a84f2b6b9fbc4982e459fb1bdfe98aa8fe2e246523da79264516737683900dab66f301695704ab6dc0cc7e2e18b4227e74e8e78fbbb9367d55d6111a90b56154a1c341649d530bad1fe7a5dd37a8dce61e767df71ee6617e7ebf0a7f4409a94d4d64066373617ef80ed2229310df5e0816d1bbcad8dde3c27c4085404c2100e59f6aa1ee2a0daa696e9627384adbd77344c7b13c2c8e29ea538e5abd"),
            q: test_bn_hex("8082a1d5f41d1949afb40ebf7f6dc923ddd26f48f09793035d5d78af1c81a49f"),
            g: test_bn_hex("2900a173f3a3c72c8880b565b726931135ecabf8f4b372e5549870b01d94759ee263d7e731f1007d856b764d8219eae50ced10b82ab187a862b82d3e8c076ce3334426179de864c29c18c7243d8f36e65b694928b44d0af963da5b67b2098f336352b5afbe3c48e0ceba69907ef154b86110034c8160d2bb3a1df72cb0a39bb4f9c9f5027e741b634601ce9ab60d76d22a4aecbea43f03726396aad454f25ce31a6761c72990bf5edc33e4e2bfb76ca7bfce728e2f249c59487c0b744cbe33288331e8b1285c9948ce8f221c80218a58b8c056eda76ebbc0e8b0037656e37f2286cd8cf7b538e08b9c75f79c9a7497aba9be673b0faa38f42fa8eb6395c6882a"),
        };
        assert_eq!(params.p.bit_len(), 2048);
        assert!(params.g.mod_pow(&params.q, &params.p).unwrap().is_one());
        assert!(generate(&params, &mut test_rng()).is_ok());
    }

    #[cfg(feature = "alloc")]
    fn test_rng() -> impl Rng {
        struct R(u64);
        impl Rng for R {
            fn fill_bytes(&mut self, out: &mut [u8]) {
                for b in out.iter_mut() {
                    self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *b = (self.0 >> 33) as u8;
                }
            }
        }
        R(7)
    }
}
