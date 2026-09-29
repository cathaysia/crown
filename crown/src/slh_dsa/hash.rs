//! SLH-DSA hash functions (FIPS 205 Sections 4.3, 11.1, 11.2).
//!
//! Six building blocks are defined for each hash family:
//!
//! * `T_l` — compress a WOTS+ or FORS public key
//! * `F`   — one WOTS+/FORS chain step
//! * `H`   — hash two tree nodes into their parent
//! * `PRF` — derive a secret element from `SK.seed`
//! * `PRF_msg` — derive the per-message randomness `R`
//! * `H_msg` — digest the message into `m` bytes
//!
//! The SHAKE parameter sets use SHAKE256 for every function (Section 11.1).
//! The SHA2 parameter sets use SHA-256/SHA-512 with a compressed 22-byte
//! address and zero padding (Sections 11.2.1 and 11.2.2).

use crate::core::{CoreRead, CoreWrite};
use crate::error::CryptoResult;
use crate::hash::sha3::new_shake256;
use crate::hash::{sha256, sha512, Hash};
use crate::mac::hmac::HMAC;

use super::adrs::Adrs;
use super::params::{Params, MAX_N};

/// Maximum digest size (SHA-512) among the SHA2 variants.
const MAX_DIGEST: usize = 64;
/// Maximum zero-pad width: `toByte(0, 128 - n)` for the category 3/5 H()/T().
const MAX_ZERO_PAD: usize = 128;

fn shake256_xof(parts: &[&[u8]], out: &mut [u8]) {
    let mut x = new_shake256();
    for p in parts {
        x.write_all(p).expect("shakewrite");
    }
    x.read(out).expect("shake read");
}

/// `Trunc_n(H(PK.seed || toByte(0, b - n) || ADRS_c || M))` (FIPS 205 §11.2).
fn sha2_hash_padded(
    p: &Params,
    pk_seed: &[u8],
    adrs: &Adrs,
    m: &[u8],
    b: usize,
    out: &mut [u8],
) {
    let n = p.n;
    debug_assert!(b >= n && b - n <= MAX_ZERO_PAD);
    let zeros = [0u8; MAX_ZERO_PAD];
    if p.big_hash && b == p.ht_bound {
        // H() and T() of categories 3 and 5 use SHA-512 with C = 128.
        let mut h = sha512::new512();
        h.write_all(pk_seed).expect("sha512 write");
        h.write_all(&zeros[..b - n]).expect("sha512 write");
        h.write_all(adrs.as_bytes()).expect("sha512 write");
        h.write_all(m).expect("sha512 write");
        out[..n].copy_from_slice(&h.sum()[..n]);
    } else {
        let mut h = sha256::new256();
        h.write_all(pk_seed).expect("sha256 write");
        h.write_all(&zeros[..b - n]).expect("sha256 write");
        h.write_all(adrs.as_bytes()).expect("sha256 write");
        h.write_all(m).expect("sha256 write");
        out[..n].copy_from_slice(&h.sum()[..n]);
    }
}

/// MGF1 (PKCS #1) with SHA-256 or SHA-512 (FIPS 205 §11.2).
fn mgf1(p: &Params, seed: &[u8], out: &mut [u8]) {
    let mut produced = 0usize;
    let mut counter: u32 = 0;
    while produced < out.len() {
        let take = if p.big_hash {
            let mut h = sha512::new512();
            h.write_all(seed).expect("mgf1 write");
            h.write_all(&counter.to_be_bytes()).expect("mgf1 write");
            let d = h.sum();
            let take = core::cmp::min(d.len(), out.len() - produced);
            out[produced..produced + take].copy_from_slice(&d[..take]);
            take
        } else {
            let mut h = sha256::new256();
            h.write_all(seed).expect("mgf1 write");
            h.write_all(&counter.to_be_bytes()).expect("mgf1 write");
            let d = h.sum();
            let take = core::cmp::min(d.len(), out.len() - produced);
            out[produced..produced + take].copy_from_slice(&d[..take]);
            take
        };
        produced += take;
        counter += 1;
    }
}

/// `T_l(PK.seed, ADRS, M_l)` — compress a WOTS+/FORS public key to `n` bytes.
pub(crate) fn t_l(p: &Params, pk_seed: &[u8], adrs: &Adrs, ml: &[u8], out: &mut [u8]) {
    let n = p.n;
    if p.is_shake {
        shake256_xof(&[pk_seed, adrs.as_bytes(), ml], &mut out[..n]);
    } else {
        sha2_hash_padded(p, pk_seed, adrs, ml, p.ht_bound, &mut out[..n]);
    }
}

/// `F(PK.seed, ADRS, M1)` — one chain step.
pub(crate) fn f(p: &Params, pk_seed: &[u8], adrs: &Adrs, m1: &[u8], out: &mut [u8]) {
    let n = p.n;
    if p.is_shake {
        shake256_xof(&[pk_seed, adrs.as_bytes(), m1], &mut out[..n]);
    } else {
        sha2_hash_padded(p, pk_seed, adrs, m1, 64, &mut out[..n]);
    }
}

/// `H(PK.seed, ADRS, M1, M2)` — parent of two tree nodes.
///
/// `m1` and `m2` are node values of `n` bytes each; only their first `n` bytes
/// are absorbed (FIPS 205 §11.1/11.2), so callers may pass longer scratch
/// buffers safely.
pub(crate) fn h(
    p: &Params,
    pk_seed: &[u8],
    adrs: &Adrs,
    m1: &[u8],
    m2: &[u8],
    out: &mut [u8],
) {
    let n = p.n;
    if p.is_shake {
        shake256_xof(&[pk_seed, adrs.as_bytes(), &m1[..n], &m2[..n]], &mut out[..n]);
    } else {
        let mut buf = [0u8; 2 * MAX_N];
        buf[..n].copy_from_slice(&m1[..n]);
        buf[n..2 * n].copy_from_slice(&m2[..n]);
        sha2_hash_padded(p, pk_seed, adrs, &buf[..2 * n], p.ht_bound, &mut out[..n]);
    }
}

/// `PRF(PK.seed, ADRS, SK.seed)` — derive one secret element.
pub(crate) fn prf(
    p: &Params,
    pk_seed: &[u8],
    adrs: &Adrs,
    sk_seed: &[u8],
    out: &mut [u8],
) {
    let n = p.n;
    if p.is_shake {
        shake256_xof(&[pk_seed, adrs.as_bytes(), sk_seed], &mut out[..n]);
    } else {
        sha2_hash_padded(p, pk_seed, adrs, sk_seed, 64, &mut out[..n]);
    }
}

/// `PRF_msg(SK.prf, opt_rand, M)` — per-message randomness `R` of `n` bytes.
pub(crate) fn prf_msg(
    p: &Params,
    sk_prf: &[u8],
    opt_rand: &[u8],
    msg: &[u8],
    out: &mut [u8],
) {
    let n = p.n;
    if p.is_shake {
        shake256_xof(&[sk_prf, opt_rand, msg], &mut out[..n]);
    } else if p.big_hash {
        let mut mac = HMAC::new(sha512::new512, sk_prf);
        mac.write_all(opt_rand).expect("hmac write");
        mac.write_all(msg).expect("hmac write");
        out[..n].copy_from_slice(&mac.sum()[..n]);
    } else {
        let mut mac = HMAC::new(sha256::new256, sk_prf);
        mac.write_all(opt_rand).expect("hmac write");
        mac.write_all(msg).expect("hmac write");
        out[..n].copy_from_slice(&mac.sum()[..n]);
    }
}

/// `H_msg(R, PK.seed, PK.root, M)` — digest the message to `m` bytes.
pub(crate) fn h_msg(
    p: &Params,
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    out: &mut [u8],
) {
    let n = p.n;
    let m = p.m;
    if p.is_shake {
        shake256_xof(&[r, pk_seed, pk_root, msg], &mut out[..m]);
    } else {
        // seed = R || PK.seed || H_big(R || PK.seed || PK.root || M)
        let mut seed = [0u8; 2 * MAX_N + MAX_DIGEST];
        seed[..n].copy_from_slice(&r[..n]);
        seed[n..2 * n].copy_from_slice(&pk_seed[..n]);
        let mut h = if p.big_hash {
            EitherHash::Big(sha512::new512())
        } else {
            EitherHash::Small(sha256::new256())
        };
        h.write_all(r).expect("hmsg write");
        h.write_all(pk_seed).expect("hmsg write");
        h.write_all(pk_root).expect("hmsg write");
        h.write_all(msg).expect("hmsg write");
        let digest_len = h.size();
        {
            let d = h.sum();
            seed[2 * n..2 * n + digest_len].copy_from_slice(&d[..digest_len]);
        }
        mgf1(p, &seed[..2 * n + digest_len], &mut out[..m]);
    }
}

/// Small helper to hold either SHA-256 or SHA-512 while streaming H_msg input.
enum EitherHash {
    Small(sha256::Sha256<32, false>),
    Big(sha512::Sha512<64>),
}

impl EitherHash {
    fn size(&self) -> usize {
        match self {
            EitherHash::Small(_) => 32,
            EitherHash::Big(_) => 64,
        }
    }
    fn sum(self) -> [u8; MAX_DIGEST] {
        let mut out = [0u8; MAX_DIGEST];
        match self {
            EitherHash::Small(mut h) => out[..32].copy_from_slice(&h.sum()),
            EitherHash::Big(mut h) => out[..64].copy_from_slice(&h.sum()),
        }
        out
    }
}

impl CoreWrite for EitherHash {
    fn write(&mut self, buf: &[u8]) -> CryptoResult<usize> {
        match self {
            EitherHash::Small(h) => h.write(buf),
            EitherHash::Big(h) => h.write(buf),
        }
    }
    fn flush(&mut self) -> CryptoResult<()> {
        Ok(())
    }
}

