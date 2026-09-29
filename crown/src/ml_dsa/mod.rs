//! ML-DSA (FIPS 204) module-lattice digital signature algorithm.
//!
//! Pure Rust port of the ML-DSA operations in OpenSSL 3.5
//! (`crypto/ml_dsa/*`), covering ML-DSA-44, ML-DSA-65 and ML-DSA-87.
//!
//! # Message encoding
//!
//! [`sign`] / [`verify`] implement the *pure* signature scheme of
//! FIPS 204 §5.2: the message representative is
//! `M' = 0x00 || len(ctx) || ctx || message` with `ctx.len() ≤ 255`.
//!
//! The internal routines also accept a pre-formed message representative
//! (`sign_prehashed` / [`verify_prehashed`]) matching OpenSSL's
//! `message-encoding:0` and `mu:1` test modes; FIPS 204 HashML-DSA
//! (§5.4, `M' = 0x01 || …`) is left to callers that construct `M'` themselves.
//!
//! # Randomness
//!
//! `rnd: Some(&[u8; 32])` produces a hedged signature; `rnd: None` is the
//! deterministic mode (`rnd = 0^256`) from FIPS 204 Algorithm 2.
//!
//! # Constant-time notes
//!
//! Comparisons of `z`/`r0`/hint counts in signing and the final `c_tilde`
//! comparison in verification use branch-light logic; the rejection-sampling
//! loops themselves are **variable time by design** (FIPS 204 §3.6.3), as in
//! the OpenSSL reference.

mod encode;
mod ntt;
mod params;
mod poly;
mod sample;
mod sign;

#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use crate::error::{CryptoError, CryptoResult};
pub use params::{MlDsaVariant, MAX_CONTEXT_STRING_LEN};

use params::params as lookup_params;

/// Encoded public-key size in bytes for `variant`.
pub fn public_key_size(variant: MlDsaVariant) -> usize {
    lookup_params(variant).pk_len
}

/// Encoded private-key size in bytes for `variant`.
pub fn private_key_size(variant: MlDsaVariant) -> usize {
    lookup_params(variant).sk_len
}

/// Encoded signature size in bytes for `variant`.
pub fn signature_size(variant: MlDsaVariant) -> usize {
    lookup_params(variant).sig_len
}

/// An ML-DSA public key (FIPS 204 `pkEncode` bytes).
#[derive(Clone)]
pub struct MlDsaPublicKey {
    variant: MlDsaVariant,
    bytes: Vec<u8>,
}

/// An ML-DSA private key (FIPS 204 `skEncode` bytes).
#[derive(Clone)]
pub struct MlDsaPrivateKey {
    variant: MlDsaVariant,
    bytes: Vec<u8>,
}

impl MlDsaPublicKey {
    /// The parameter set this key belongs to.
    pub fn variant(&self) -> MlDsaVariant {
        self.variant
    }

    /// FIPS 204 `pkEncode` output.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// FIPS 204 `pkDecode` (length-checked).
    pub fn from_bytes(variant: MlDsaVariant, bytes: &[u8]) -> CryptoResult<Self> {
        let p = lookup_params(variant);
        if bytes.len() != p.pk_len {
            return Err(CryptoError::InvalidKeySize {
                expected: "variant public key length",
                actual: bytes.len(),
            });
        }
        // Validate the packing (t1 coefficients fit in 10 bits by construction,
        // but reject a wrong length early).
        encode::pk_decode(bytes, p.k).ok_or(CryptoError::StrError("ml-dsa invalid public key"))?;
        Ok(MlDsaPublicKey {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

impl MlDsaPrivateKey {
    /// The parameter set this key belongs to.
    pub fn variant(&self) -> MlDsaVariant {
        self.variant
    }

    /// FIPS 204 `skEncode` output.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// FIPS 204 `skDecode` (length and coefficient-range checked).
    pub fn from_bytes(variant: MlDsaVariant, bytes: &[u8]) -> CryptoResult<Self> {
        let p = lookup_params(variant);
        if bytes.len() != p.sk_len {
            return Err(CryptoError::InvalidKeySize {
                expected: "variant private key length",
                actual: bytes.len(),
            });
        }
        sign::expand_priv(&p, bytes)?;
        Ok(MlDsaPrivateKey {
            variant,
            bytes: bytes.to_vec(),
        })
    }

    /// Derive the matching public key (FIPS 204 `pkEncode`).
    pub fn public_key(&self) -> CryptoResult<MlDsaPublicKey> {
        let p = lookup_params(self.variant);
        let priv_exp = sign::expand_priv(&p, &self.bytes)?;
        let (t1, _t0) = sign::public_from_private(&p, &priv_exp.rho, &priv_exp.s1, &priv_exp.s2);
        let pk = encode::pk_encode(&priv_exp.rho, &t1);
        Ok(MlDsaPublicKey {
            variant: self.variant,
            bytes: pk,
        })
    }
}

/// Generate an ML-DSA key pair from a 32-byte seed
/// (FIPS 204 Algorithm 6 `ML-DSA.KeyGen_internal`).
pub fn keygen(
    variant: MlDsaVariant,
    seed: &[u8; 32],
) -> CryptoResult<(MlDsaPublicKey, MlDsaPrivateKey)> {
    let p = lookup_params(variant);
    let (pk, sk) = sign::keygen_internal(&p, seed)?;
    Ok((
        MlDsaPublicKey { variant, bytes: pk },
        MlDsaPrivateKey { variant, bytes: sk },
    ))
}

/// Sign `message` with context string `ctx` using the pure ML-DSA scheme
/// (FIPS 204 Algorithm 2 `ML-DSA.Sign`).
///
/// `rnd = Some(_)` is hedged signing; `rnd = None` is deterministic
/// (`rnd = 0^256`).
pub fn sign(
    sk: &MlDsaPrivateKey,
    message: &[u8],
    ctx: &[u8],
    rnd: Option<&[u8; 32]>,
) -> CryptoResult<Vec<u8>> {
    let m_prime = sign::encode_pure(message, ctx)?;
    sign_prehashed(sk, &m_prime, rnd)
}

/// Verify a pure ML-DSA signature over `message` with context `ctx`
/// (FIPS 204 Algorithm 3 `ML-DSA.Verify`).
///
/// Returns `Ok(false)` for an invalid signature; `Err` only for malformed
/// inputs (e.g. over-long context).
pub fn verify(pk: &MlDsaPublicKey, message: &[u8], ctx: &[u8], sig: &[u8]) -> CryptoResult<bool> {
    let m_prime = sign::encode_pure(message, ctx)?;
    verify_prehashed(pk, &m_prime, sig)
}

/// Sign a pre-formed message representative `M'` (FIPS 204 Algorithm 7
/// `ML-DSA.Sign_internal`). This covers OpenSSL's `message-encoding:0`
/// (HashML-DSA callers build `M'` themselves).
pub fn sign_prehashed(
    sk: &MlDsaPrivateKey,
    m_prime: &[u8],
    rnd: Option<&[u8; 32]>,
) -> CryptoResult<Vec<u8>> {
    let p = lookup_params(sk.variant);
    let priv_exp = sign::expand_priv(&p, &sk.bytes)?;
    let rnd = rnd.copied().unwrap_or([0u8; 32]);
    sign::sign_internal(&p, &priv_exp, m_prime, &rnd, false)
}

/// Verify a signature over a pre-formed message representative `M'`
/// (FIPS 204 Algorithm 8 `ML-DSA.Verify_internal`).
pub fn verify_prehashed(pk: &MlDsaPublicKey, m_prime: &[u8], sig: &[u8]) -> CryptoResult<bool> {
    let p = lookup_params(pk.variant);
    if sig.len() != p.sig_len {
        return Ok(false);
    }
    let pub_exp = sign::expand_pub(&p, &pk.bytes)?;
    sign::verify_internal(&p, &pub_exp, m_prime, sig, false)
}

/// Sign when the caller already holds the 64-byte message representative μ
/// (OpenSSL `mu:1` mode): no `tr || M'` hashing is performed.
pub fn sign_mu(sk: &MlDsaPrivateKey, mu: &[u8], rnd: Option<&[u8; 32]>) -> CryptoResult<Vec<u8>> {
    let p = lookup_params(sk.variant);
    let priv_exp = sign::expand_priv(&p, &sk.bytes)?;
    let rnd = rnd.copied().unwrap_or([0u8; 32]);
    sign::sign_internal(&p, &priv_exp, mu, &rnd, true)
}

/// Verify when the caller already holds the 64-byte message representative μ
/// (OpenSSL `mu:1` mode).
pub fn verify_mu(pk: &MlDsaPublicKey, mu: &[u8], sig: &[u8]) -> CryptoResult<bool> {
    let p = lookup_params(pk.variant);
    if sig.len() != p.sig_len {
        return Ok(false);
    }
    let pub_exp = sign::expand_pub(&p, &pk.bytes)?;
    sign::verify_internal(&p, &pub_exp, mu, sig, true)
}
