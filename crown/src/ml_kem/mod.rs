//! ML-KEM (FIPS 203) module-lattice key encapsulation mechanism.
//!
//! Ported from OpenSSL 3.5.8 `crypto/ml_kem/ml_kem.c`. Pure software Rust,
//! `no_std + alloc`. SHA3/SHAKE come from [`crate::hash::sha3`].
//!
//! Supported operations:
//!
//! * deterministic key generation from a 64-byte seed `(d ‖ z)`,
//! * encapsulation from a 32-byte message `m`,
//! * decapsulation with a constant-time Fujisaki–Okamoto transform and
//!   implicit rejection on ciphertext mismatch.
//!
//! ```
//! use crown::ml_kem::{keygen, encapsulate, decapsulate, MlKemVariant};
//!
//! let seed = [7u8; 64];
//! let (pk, sk) = keygen(MlKemVariant::MlKem768, &seed).unwrap();
//! let m = [9u8; 32];
//! let (ct, ss1) = encapsulate(&pk, &m).unwrap();
//! let ss2 = decapsulate(&sk, &ct).unwrap();
//! assert_eq!(ss1, ss2);
//! ```

mod ntt;
#[cfg(test)]
mod tests;

use crate::core::{CoreRead, CoreWrite};
use crate::error::{CryptoError, CryptoResult};
use crate::hash::sha3;
use crate::utils::subtle::constant_time_eq;
use alloc::vec;
use alloc::vec::Vec;

use ntt::{add_assign, intt, mul_pointwise, ntt, sub_assign, zero, Poly, N, Q};

/// ML-KEM parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKemVariant {
    /// ML-KEM-512 (k = 2, η₁ = 3, η₂ = 2, dᵤ = 10, dᵥ = 4).
    MlKem512,
    /// ML-KEM-768 (k = 3, η₁ = 2, η₂ = 2, dᵤ = 10, dᵥ = 4).
    MlKem768,
    /// ML-KEM-1024 (k = 4, η₁ = 2, η₂ = 2, dᵤ = 11, dᵥ = 5).
    MlKem1024,
}

#[derive(Clone, Copy)]
struct Params {
    k: usize,
    eta1: u8,
    eta2: u8,
    du: u8,
    dv: u8,
}

impl MlKemVariant {
    fn params(self) -> Params {
        match self {
            MlKemVariant::MlKem512 => Params {
                k: 2,
                eta1: 3,
                eta2: 2,
                du: 10,
                dv: 4,
            },
            MlKemVariant::MlKem768 => Params {
                k: 3,
                eta1: 2,
                eta2: 2,
                du: 10,
                dv: 4,
            },
            MlKemVariant::MlKem1024 => Params {
                k: 4,
                eta1: 2,
                eta2: 2,
                du: 11,
                dv: 5,
            },
        }
    }

    /// Encapsulated key length in bytes: `384·k + 32`.
    pub fn public_key_len(self) -> usize {
        384 * self.params().k + 32
    }

    /// Decapsulation key length in bytes: `768·k + 96`.
    pub fn private_key_len(self) -> usize {
        2 * self.public_key_len() + 32
    }

    /// Ciphertext length in bytes: `32·(dᵤ·k + dᵥ)`.
    pub fn ciphertext_len(self) -> usize {
        let p = self.params();
        32 * (p.du as usize * p.k + p.dv as usize)
    }

    /// Shared secret length in bytes.
    pub fn shared_secret_len(self) -> usize {
        32
    }
}

/// ML-KEM encapsulation (public) key.
#[derive(Clone)]
pub struct MlKemPublicKey {
    variant: MlKemVariant,
    /// Wire encoding: `ByteEncode₁₂(t̂) ‖ ρ`.
    bytes: Vec<u8>,
}

/// ML-KEM decapsulation (private) key.
#[derive(Clone)]
pub struct MlKemPrivateKey {
    variant: MlKemVariant,
    /// Wire encoding: `ByteEncode₁₂(ŝ) ‖ ek ‖ H(ek) ‖ z`.
    bytes: Vec<u8>,
}

impl MlKemPublicKey {
    /// Serialized encapsulation key (`384·k + 32` bytes).
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parse a serialized encapsulation key.
    pub fn from_bytes(variant: MlKemVariant, bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != variant.public_key_len() {
            return Err(CryptoError::InvalidLength);
        }
        // Reject 12-bit coefficients that are ≥ q (FIPS 203 ByteDecode₁₂).
        let p = variant.params();
        for i in 0..p.k {
            let chunk = &bytes[i * 384..(i + 1) * 384];
            for c in decode_poly_12(chunk)?.iter() {
                if *c >= Q {
                    return Err(CryptoError::StrError(
                        "ml-kem: public key coefficient out of range",
                    ));
                }
            }
        }
        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }

    /// Parameter set of this key.
    pub fn variant(&self) -> MlKemVariant {
        self.variant
    }
}

impl MlKemPrivateKey {
    /// Serialized decapsulation key (`768·k + 96` bytes).
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parse a serialized decapsulation key.
    pub fn from_bytes(variant: MlKemVariant, bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != variant.private_key_len() {
            return Err(CryptoError::InvalidLength);
        }
        let p = variant.params();
        let vec_bytes = 384 * p.k;
        // ŝ must decode losslessly.
        for i in 0..p.k {
            let chunk = &bytes[i * 384..(i + 1) * 384];
            for c in decode_poly_12(chunk)?.iter() {
                if *c >= Q {
                    return Err(CryptoError::StrError(
                        "ml-kem: private key coefficient out of range",
                    ));
                }
            }
        }
        // Embedded public key must be valid and its hash must match.
        let ek = &bytes[vec_bytes..vec_bytes + vec_bytes + 32];
        MlKemPublicKey::from_bytes(variant, ek)?;
        let h = sha3::sum256(ek);
        if !constant_time_eq(&h, &bytes[vec_bytes + ek.len()..vec_bytes + ek.len() + 32]) {
            return Err(CryptoError::StrError("ml-kem: public key hash mismatch"));
        }
        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }

    /// Parameter set of this key.
    pub fn variant(&self) -> MlKemVariant {
        self.variant
    }
}

// ---------------------------------------------------------------------------
// SHA3 / SHAKE helpers
// ---------------------------------------------------------------------------

fn sha3_256(data: &[u8]) -> [u8; 32] {
    sha3::sum256(data)
}

fn sha3_512(data: &[u8]) -> [u8; 64] {
    sha3::sum512(data)
}

/// SHAKE-256 with arbitrary output length (FIPS 203 PRF / J).
fn shake256(data: &[u8], out: &mut [u8]) {
    let mut h = sha3::new_shake256();
    h.write_all(data).expect("shake write");
    h.read_exact(out).expect("shake read");
}

// ---------------------------------------------------------------------------
// Encoding (FIPS 203 §4.2.1)
// ---------------------------------------------------------------------------

/// ByteEncode_d of one polynomial into `256·d/8` bytes.
fn encode_poly(f: &Poly, d: u8, out: &mut [u8]) {
    debug_assert_eq!(out.len(), N * d as usize / 8);
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    let mut idx = 0usize;
    let mask = (1u32 << d) - 1;
    for &x in f.iter() {
        acc |= (x as u32 & mask) << nbits;
        nbits += d as u32;
        while nbits >= 8 {
            out[idx] = acc as u8;
            idx += 1;
            acc >>= 8;
            nbits -= 8;
        }
    }
    if nbits > 0 {
        out[idx] = acc as u8;
    }
}

/// ByteDecode_d of one polynomial from `256·d/8` bytes. Coefficients may
/// exceed q when d = 12; callers that require lossless decoding check that.
fn decode_poly(data: &[u8], d: u8) -> Poly {
    let mut f = zero();
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    let mut idx = 0usize;
    let mask = (1u32 << d) - 1;
    for slot in f.iter_mut() {
        while nbits < d as u32 {
            acc |= (data[idx] as u32) << nbits;
            idx += 1;
            nbits += 8;
        }
        *slot = (acc & mask) as u16;
        acc >>= d;
        nbits -= d as u32;
    }
    f
}

/// ByteDecode₁₂, erroring when any coefficient is ≥ q.
fn decode_poly_12(data: &[u8]) -> CryptoResult<Poly> {
    let f = decode_poly(data, 12);
    for c in f.iter() {
        if *c >= Q {
            return Err(CryptoError::StrError("ml-kem: coefficient out of range"));
        }
    }
    Ok(f)
}

/// Compress_d(x) = round(2^d / q · x) mod 2^d.
fn compress(x: u16, d: u8) -> u16 {
    // round(2^d · x / q) computed exactly in u64 for the small ranges used.
    let num = ((1u64 << d) * x as u64) + (Q as u64 / 2);
    (num / Q as u64) as u16 & ((1u16 << d) - 1)
}

/// Decompress_d(x) = round(q / 2^d · x).
fn decompress(x: u16, d: u8) -> u16 {
    (((Q as u32 * x as u32) + (1u32 << (d - 1))) >> d) as u16
}

// ---------------------------------------------------------------------------
// Sampling (FIPS 203 §4.2.2)
// ---------------------------------------------------------------------------

/// SampleNTT: rejection-sample a uniform polynomial from SHAKE-128(ρ ‖ j ‖ i).
fn sample_ntt(rho: &[u8; 32], i: u8, j: u8) -> Poly {
    let mut input = [0u8; 34];
    input[..32].copy_from_slice(rho);
    input[32] = j;
    input[33] = i;
    let mut f = zero();
    let mut n = 0usize;
    let mut h = sha3::new_shake128();
    h.write_all(&input).expect("shake write");
    while n < N {
        let mut buf = [0u8; 168]; // one SHAKE-128 block; 168 % 3 == 0
        h.read_exact(&mut buf).expect("shake read");
        let mut idx = 0usize;
        while idx + 3 <= buf.len() && n < N {
            let d1 = buf[idx] as u16 | ((buf[idx + 1] as u16 & 0x0f) << 8);
            let d2 = (buf[idx + 1] as u16 >> 4) | ((buf[idx + 2] as u16) << 4);
            idx += 3;
            if d1 < Q {
                f[n] = d1;
                n += 1;
            }
            if n < N && d2 < Q {
                f[n] = d2;
                n += 1;
            }
        }
    }
    f
}

/// SamplePolyCBD_η from PRF_η(s, b) = SHAKE-256(s ‖ b) with 64·η output bytes.
fn sample_cbd(seed: &[u8], nonce: u8, eta: u8) -> Poly {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(&seed[..32]);
    input[32] = nonce;
    let buflen = 64 * eta as usize;
    let mut buf = vec![0u8; buflen];
    shake256(&input, &mut buf);
    let mut f = zero();
    for i in 0..N {
        let mut x = 0i32;
        let mut y = 0i32;
        for j in 0..eta as usize {
            let bit = |p: usize| ((buf[p / 8] >> (p % 8)) & 1) as i32;
            x += bit(2 * i * eta as usize + j);
            y += bit(2 * i * eta as usize + eta as usize + j);
        }
        // x − y ∈ [−η, η]; map into [0, q) branchlessly.
        let diff = (x - y) as i16;
        let mask = (diff >> 15) as u16; // 0xffff if negative
        f[i] = ((diff as u16) & !mask) | ((diff as u16).wrapping_add(Q) & mask);
    }
    f
}

// ---------------------------------------------------------------------------
// K-PKE (FIPS 203 §5)
// ---------------------------------------------------------------------------

/// Generate the expanded matrix Â where `Â[i][j] = SampleNTT(ρ ‖ j ‖ i)`.
fn sample_matrix(rho: &[u8; 32], k: usize) -> Vec<Poly> {
    let mut a = Vec::with_capacity(k * k);
    for i in 0..k {
        for j in 0..k {
            a.push(sample_ntt(rho, i as u8, j as u8));
        }
    }
    a
}

/// K-PKE.KeyGen (FIPS 203 Algorithm 13). Returns (dk_pke, ek).
fn k_pke_keygen(d: &[u8; 32], p: &Params) -> (Vec<u8>, Vec<u8>) {
    let k = p.k;
    // (ρ, σ) ← G(d ‖ k)
    let mut g_in = [0u8; 33];
    g_in[..32].copy_from_slice(d);
    g_in[32] = k as u8;
    let g = sha3_512(&g_in);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    let sigma = &g[32..];

    let a = sample_matrix(&rho, k);

    let mut s: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        let mut p_i = sample_cbd(sigma, i as u8, p.eta1);
        ntt(&mut p_i);
        s.push(p_i);
    }
    let mut e: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        let mut p_i = sample_cbd(sigma, (k + i) as u8, p.eta1);
        ntt(&mut p_i);
        e.push(p_i);
    }

    // t̂ = Â ◦ ŝ + ê
    let mut t = e;
    for i in 0..k {
        for j in 0..k {
            let prod = mul_pointwise(&a[i * k + j], &s[j]);
            add_assign(&mut t[i], &prod);
        }
    }

    let mut ek = vec![0u8; 384 * k + 32];
    for i in 0..k {
        encode_poly(&t[i], 12, &mut ek[i * 384..(i + 1) * 384]);
    }
    ek[384 * k..].copy_from_slice(&rho);

    let mut dk = vec![0u8; 384 * k];
    for i in 0..k {
        encode_poly(&s[i], 12, &mut dk[i * 384..(i + 1) * 384]);
    }
    (dk, ek)
}

/// K-PKE.Encrypt (FIPS 203 Algorithm 14).
fn k_pke_encrypt(ek: &[u8], m: &[u8; 32], r: &[u8; 32], p: &Params) -> Vec<u8> {
    let k = p.k;
    let mut t: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        t.push(decode_poly(&ek[i * 384..(i + 1) * 384], 12));
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * k..]);
    let a = sample_matrix(&rho, k);

    let mut y: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        let mut p_i = sample_cbd(r, i as u8, p.eta1);
        ntt(&mut p_i);
        y.push(p_i);
    }
    let mut e1: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        e1.push(sample_cbd(r, (k + i) as u8, p.eta2));
    }
    let e2 = sample_cbd(r, (2 * k) as u8, p.eta2);

    // u = NTT⁻¹(Âᵀ ◦ ŷ) + e1
    let mut u: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        let mut acc = zero();
        for j in 0..k {
            // (Âᵀ)[i][j] = Â[j][i]
            let prod = mul_pointwise(&a[j * k + i], &y[j]);
            add_assign(&mut acc, &prod);
        }
        intt(&mut acc);
        add_assign(&mut acc, &e1[i]);
        u.push(acc);
    }

    // v = NTT⁻¹(t̂ᵀ ◦ ŷ) + e2 + Decompress₁(m)
    let mut v = zero();
    for j in 0..k {
        let prod = mul_pointwise(&t[j], &y[j]);
        add_assign(&mut v, &prod);
    }
    intt(&mut v);
    add_assign(&mut v, &e2);
    // μ = Decompress₁(ByteDecode₁(m)): add ⌈q/2⌉ for each set message bit.
    let mu = decode_poly(m, 1);
    for i in 0..N {
        let mask = 0u16.wrapping_sub(mu[i] & 1); // 0xffff if bit set
        v[i] = ntt::add(v[i], mask & Q.div_ceil(2));
    }

    let mut ct = vec![0u8; p.du as usize * 32 * k + p.dv as usize * 32];
    for i in 0..k {
        let mut c = zero();
        for j in 0..N {
            c[j] = compress(u[i][j], p.du);
        }
        encode_poly(
            &c,
            p.du,
            &mut ct[i * 32 * p.du as usize..(i + 1) * 32 * p.du as usize],
        );
    }
    let off = 32 * p.du as usize * k;
    let mut c = zero();
    for j in 0..N {
        c[j] = compress(v[j], p.dv);
    }
    encode_poly(&c, p.dv, &mut ct[off..]);
    ct
}

/// K-PKE.Decrypt (FIPS 203 Algorithm 15).
fn k_pke_decrypt(dk: &[u8], ct: &[u8], p: &Params) -> [u8; 32] {
    let k = p.k;
    let mut s: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        s.push(decode_poly(&dk[i * 384..(i + 1) * 384], 12));
    }
    let u_bytes = 32 * p.du as usize * k;
    let mut u: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        let raw = decode_poly(
            &ct[i * 32 * p.du as usize..(i + 1) * 32 * p.du as usize],
            p.du,
        );
        let mut d = zero();
        for j in 0..N {
            d[j] = decompress(raw[j], p.du);
        }
        u.push(d);
    }
    let raw_v = decode_poly(&ct[u_bytes..], p.dv);
    let mut v = zero();
    for j in 0..N {
        v[j] = decompress(raw_v[j], p.dv);
    }

    // w = v − NTT⁻¹(ŝᵀ ◦ NTT(u))
    let mut acc = zero();
    for i in 0..k {
        let mut uh = u[i];
        ntt(&mut uh);
        let prod = mul_pointwise(&s[i], &uh);
        add_assign(&mut acc, &prod);
    }
    intt(&mut acc);
    sub_assign(&mut v, &acc);

    let mut m = [0u8; 32];
    for i in 0..N {
        m[i / 8] |= ((compress(v[i], 1) & 1) as u8) << (i % 8);
    }
    m
}

// ---------------------------------------------------------------------------
// ML-KEM (FIPS 203 §7)
// ---------------------------------------------------------------------------

/// Generate an ML-KEM key pair deterministically from a 64-byte seed `(d ‖ z)`.
///
/// The seed is expanded with `G(d ‖ k)` into `(ρ, σ)`; `ρ` generates the
/// public matrix, `σ` the secret and error vectors. The trailing 32 bytes `z`
/// are stored verbatim as the implicit-rejection secret.
pub fn keygen(
    variant: MlKemVariant,
    seed: &[u8; 64],
) -> CryptoResult<(MlKemPublicKey, MlKemPrivateKey)> {
    let p = variant.params();
    let mut d = [0u8; 32];
    d.copy_from_slice(&seed[..32]);
    let (dk_pke, ek) = k_pke_keygen(&d, &p);
    let h = sha3_256(&ek);
    let mut sk_bytes = Vec::with_capacity(variant.private_key_len());
    sk_bytes.extend_from_slice(&dk_pke);
    sk_bytes.extend_from_slice(&ek);
    sk_bytes.extend_from_slice(&h);
    sk_bytes.extend_from_slice(&seed[32..]);
    Ok((
        MlKemPublicKey { variant, bytes: ek },
        MlKemPrivateKey {
            variant,
            bytes: sk_bytes,
        },
    ))
}

/// Encapsulate to `pk` using the 32-byte message `m` as the FO seed.
///
/// Returns `(ciphertext, shared_secret)`.
pub fn encapsulate(pk: &MlKemPublicKey, m: &[u8; 32]) -> CryptoResult<(Vec<u8>, [u8; 32])> {
    let p = pk.variant.params();
    let ek = &pk.bytes;
    let h = sha3_256(ek);
    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(m);
    g_in[32..].copy_from_slice(&h);
    let g = sha3_512(&g_in);
    let mut k = [0u8; 32];
    k.copy_from_slice(&g[..32]);
    let mut r = [0u8; 32];
    r.copy_from_slice(&g[32..]);
    let ct = k_pke_encrypt(ek, m, &r, &p);
    Ok((ct, k))
}

/// Decapsulate `ct` with `sk`, recovering the shared secret.
///
/// Wrong-length ciphertexts are rejected. On re-encryption mismatch the
/// implicit-rejection secret `J(z ‖ c)` is returned in constant time.
pub fn decapsulate(sk: &MlKemPrivateKey, ct: &[u8]) -> CryptoResult<[u8; 32]> {
    let p = sk.variant.params();
    if ct.len() != sk.variant.ciphertext_len() {
        return Err(CryptoError::InvalidLength);
    }
    let bytes = &sk.bytes;
    let vec_bytes = 384 * p.k;
    let dk_pke = &bytes[..vec_bytes];
    let ek = &bytes[vec_bytes..vec_bytes + ek_len(p.k)];
    let h = &bytes[vec_bytes + ek_len(p.k)..vec_bytes + ek_len(p.k) + 32];
    let z = &bytes[vec_bytes + ek_len(p.k) + 32..];

    let m_prime = k_pke_decrypt(dk_pke, ct, &p);
    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(&m_prime);
    g_in[32..].copy_from_slice(h);
    let g = sha3_512(&g_in);
    let mut k_prime = [0u8; 32];
    k_prime.copy_from_slice(&g[..32]);
    let mut r_prime = [0u8; 32];
    r_prime.copy_from_slice(&g[32..]);

    let ct_prime = k_pke_encrypt(ek, &m_prime, &r_prime, &p);

    // J(z ‖ c) — implicit rejection, computed unconditionally.
    let mut j_in = Vec::with_capacity(32 + ct.len());
    j_in.extend_from_slice(z);
    j_in.extend_from_slice(ct);
    let mut k_fail = [0u8; 32];
    shake256(&j_in, &mut k_fail);

    // Constant-time select: equal ciphertexts yield k_prime, else k_fail.
    let eq = constant_time_eq(ct, &ct_prime);
    let mask = 0u8.wrapping_sub(eq as u8); // 0xff on match, 0x00 otherwise
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (k_prime[i] & mask) | (k_fail[i] & !mask);
    }
    Ok(out)
}

fn ek_len(k: usize) -> usize {
    384 * k + 32
}
