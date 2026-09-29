//! ML-DSA signature generation and verification (FIPS 204 Algorithms 7 & 8).
//!
//! Rejection sampling in signing is variable-time by design: a rejected
//! candidate is indistinguishable from an independent fresh attempt.

use alloc::vec;
use alloc::vec::Vec;

use crate::core::{CoreRead, CoreWrite};
use crate::error::{CryptoError, CryptoResult};
use crate::hash::sha3::{new_shake256, Shake};
use crate::utils::subtle::constant_time_eq;

use super::encode::{
    pk_encode, sig_decode, sig_encode, sk_decode, sk_encode, w1_encode,
};
use super::ntt::{ntt, ntt_inverse, ntt_mult};
use super::params::{
    Params, K_BYTES, MU_BYTES, PRIV_SEED_BYTES, RHO_BYTES, RHO_PRIME_BYTES, SEED_BYTES, TR_BYTES,
};
use super::poly::{
    make_hint, poly_add, poly_count_ones, poly_max_mod, poly_max_signed, poly_sub, power2_round,
    use_hint, Poly,
};
use super::sample::{expand_a, expand_mask_vector, expand_s, sample_in_ball_ntt};

/// SHAKE256 XOF over concatenated inputs, squeezing `out.len()` bytes.
fn shake256_xof(parts: &[&[u8]], out: &mut [u8]) {
    let mut h: Shake<64> = new_shake256();
    for p in parts {
        h.write_all(p).expect("shake write");
    }
    h.read_exact(out).expect("shake read");
}

/// Fully expanded private key material used by sign/verify internals.
pub(crate) struct ExpandedPriv {
    pub rho: [u8; RHO_BYTES],
    pub k_seed: [u8; K_BYTES],
    pub tr: [u8; TR_BYTES],
    pub s1: Vec<Poly>,
    pub s2: Vec<Poly>,
    pub t0: Vec<Poly>,
}

/// Fully expanded public key material.
pub(crate) struct ExpandedPub {
    pub rho: [u8; RHO_BYTES],
    pub tr: [u8; TR_BYTES],
    pub t1: Vec<Poly>,
}

/// FIPS 204 Algorithm 6 `ML-DSA.KeyGen_internal`.
pub(crate) fn keygen_internal(
    p: &Params,
    seed: &[u8; SEED_BYTES],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    // augmented = seed || k || l
    let mut augmented = [0u8; SEED_BYTES + 2];
    augmented[..SEED_BYTES].copy_from_slice(seed);
    augmented[SEED_BYTES] = p.k as u8;
    augmented[SEED_BYTES + 1] = p.l as u8;

    // (rho, priv_seed, K) = SHAKE256(augmented, 32 + 64 + 32)
    let mut expanded = [0u8; RHO_BYTES + PRIV_SEED_BYTES + K_BYTES];
    shake256_xof(&[&augmented], &mut expanded);
    let mut rho = [0u8; RHO_BYTES];
    rho.copy_from_slice(&expanded[..RHO_BYTES]);
    let mut priv_seed = [0u8; PRIV_SEED_BYTES];
    priv_seed.copy_from_slice(&expanded[RHO_BYTES..RHO_BYTES + PRIV_SEED_BYTES]);
    let mut k_seed = [0u8; K_BYTES];
    k_seed.copy_from_slice(&expanded[RHO_BYTES + PRIV_SEED_BYTES..]);

    let (s1, s2) = expand_s(&priv_seed, p.eta, p.l, p.k);
    let (t1, t0) = public_from_private(p, &rho, &s1, &s2);

    let pk = pk_encode(&rho, &t1);
    let mut tr = [0u8; TR_BYTES];
    shake256_xof(&[&pk], &mut tr);
    let sk = sk_encode(&rho, &k_seed, &tr, &s1, &s2, &t0, p.eta);
    Ok((pk, sk))
}

/// Compute `t = A·s1 + s2` and split into `(t1, t0)` (FIPS 204 Alg 6 steps 6–7).
pub(crate) fn public_from_private(
    p: &Params,
    rho: &[u8; RHO_BYTES],
    s1: &[Poly],
    s2: &[Poly],
) -> (Vec<Poly>, Vec<Poly>) {
    let a_ntt = expand_a(rho, p.k, p.l);
    let mut s1_ntt: Vec<Poly> = s1.to_vec();
    for poly in &mut s1_ntt {
        ntt(&mut poly.coeff);
    }
    let t = mat_vec_mul(&a_ntt, &s1_ntt, p.k, p.l);
    let mut t = t;
    for poly in &mut t {
        ntt_inverse(&mut poly.coeff);
    }
    let mut t_full = t;
    for i in 0..p.k {
        let tmp = t_full[i].clone();
        poly_add(&tmp, &s2[i], &mut t_full[i]);
    }
    let mut t1 = Vec::with_capacity(p.k);
    let mut t0 = Vec::with_capacity(p.k);
    for poly in &t_full {
        let (r1, r0) = split_power2_round(poly);
        t1.push(r1);
        t0.push(r0);
    }
    (t1, t0)
}

fn split_power2_round(t: &Poly) -> (Poly, Poly) {
    let mut t1 = Poly::zero();
    let mut t0 = Poly::zero();
    for i in 0..t.coeff.len() {
        let (r1, r0) = power2_round(t.coeff[i]);
        t1.coeff[i] = r1;
        t0.coeff[i] = r0;
    }
    (t1, t0)
}

/// Matrix–vector product in NTT domain: `out_i = Σ_j A[i][j] * v_j`.
fn mat_vec_mul(a: &[Poly], v: &[Poly], k: usize, l: usize) -> Vec<Poly> {
    let mut out: Vec<Poly> = (0..k).map(|_| Poly::zero()).collect();
    let mut product = Poly::zero();
    for i in 0..k {
        for j in 0..l {
            ntt_mult(&a[i * l + j].coeff, &v[j].coeff, &mut product.coeff);
            let tmp = out[i].clone();
            poly_add(&tmp, &product, &mut out[i]);
        }
    }
    out
}

/// Scale `t1` by 2^d and transform to NTT (used by verification).
fn scale_power2_round_ntt(t1: &[Poly]) -> Vec<Poly> {
    t1.iter()
        .map(|p| {
            let mut out = Poly::zero();
            for i in 0..out.coeff.len() {
                out.coeff[i] = p.coeff[i] << super::params::D_BITS;
            }
            ntt(&mut out.coeff);
            out
        })
        .collect()
}

/// Vector `HighBits`.
fn vec_high_bits(v: &[Poly], gamma2: u32) -> Vec<Poly> {
    v.iter()
        .map(|p| {
            let mut out = Poly::zero();
            for i in 0..out.coeff.len() {
                out.coeff[i] = super::poly::high_bits(p.coeff[i], gamma2);
            }
            out
        })
        .collect()
}

/// Vector `LowBits` into `u32` coefficients (signed values).
fn vec_low_bits(v: &[Poly], gamma2: u32) -> Vec<Poly> {
    v.iter()
        .map(|p| {
            let mut out = Poly::zero();
            for i in 0..out.coeff.len() {
                out.coeff[i] = super::poly::low_bits(p.coeff[i], gamma2) as u32;
            }
            out
        })
        .collect()
}

fn vec_max_mod(v: &[Poly]) -> u32 {
    v.iter().map(poly_max_mod).fold(0, u32::max)
}

fn vec_max_signed(v: &[Poly]) -> u32 {
    v.iter().map(poly_max_signed).fold(0, u32::max)
}

fn vec_count_ones(v: &[Poly]) -> usize {
    v.iter().map(poly_count_ones).sum()
}

/// FIPS 204 Algorithm 7 `ML-DSA.Sign_internal(sk, M', rnd)`.
///
/// When `msg_is_mu` is true, `m_prime` is the already-computed 64-byte
/// message representative μ (OpenSSL `mu:1` mode) and is used directly.
pub(crate) fn sign_internal(
    p: &Params,
    priv_exp: &ExpandedPriv,
    m_prime: &[u8],
    rnd: &[u8; 32],
    msg_is_mu: bool,
) -> CryptoResult<Vec<u8>> {
    let k = p.k;
    let l = p.l;
    let gamma1 = p.gamma1;
    let gamma2 = p.gamma2;
    let w1_len = p.w1_encoded_len();

    // μ = SHAKE256(tr || M', 64) — unless M' already is μ.
    let mu = if msg_is_mu {
        if m_prime.len() != MU_BYTES {
            return Err(CryptoError::StrError("ml-dsa mu must be 64 bytes"));
        }
        let mut mu = [0u8; MU_BYTES];
        mu.copy_from_slice(m_prime);
        mu
    } else {
        let mut mu = [0u8; MU_BYTES];
        shake256_xof(&[&priv_exp.tr, m_prime], &mut mu);
        mu
    };

    // ρ' = SHAKE256(K || rnd || μ, 64)
    let mut rho_prime = [0u8; RHO_PRIME_BYTES];
    shake256_xof(&[&priv_exp.k_seed, rnd, &mu], &mut rho_prime);

    let a_ntt = expand_a(&priv_exp.rho, k, l);
    let mut s1_ntt = priv_exp.s1.clone();
    for poly in &mut s1_ntt {
        ntt(&mut poly.coeff);
    }
    let mut s2_ntt = priv_exp.s2.clone();
    for poly in &mut s2_ntt {
        ntt(&mut poly.coeff);
    }
    let mut t0_ntt = priv_exp.t0.clone();
    for poly in &mut t0_ntt {
        ntt(&mut poly.coeff);
    }

    // κ counts consumed mask polynomials; must stay below 2^16.
    let mut kappa: u32 = 0;
    loop {
        if kappa as usize + l > 65536 {
            return Err(CryptoError::StrError("ml-dsa signing failed"));
        }
        let y = expand_mask_vector(&rho_prime, kappa, gamma1, l);
        let mut y_ntt = y.clone();
        for poly in &mut y_ntt {
            ntt(&mut poly.coeff);
        }

        // w = A·y ; w1 = HighBits(w)
        let mut w = mat_vec_mul(&a_ntt, &y_ntt, k, l);
        for poly in &mut w {
            ntt_inverse(&mut poly.coeff);
        }
        let w1 = vec_high_bits(&w, gamma2);
        let w1_encoded = w1_encode(&w1, gamma2);
        debug_assert_eq!(w1_encoded.len(), w1_len);

        // c_tilde = SHAKE256(μ || w1Encode(w1), λ/4)
        let c_tilde_len = p.c_tilde_len();
        let mut c_tilde = vec![0u8; c_tilde_len];
        shake256_xof(&[&mu, &w1_encoded], &mut c_tilde);

        let c_ntt = sample_in_ball_ntt(&c_tilde, p.tau);

        // cs1 = NTT^-1(NTT(s1) ∘ c) ; cs2 = NTT^-1(NTT(s2) ∘ c)
        let mut cs1 = vec![Poly::zero(); l];
        let mut cs2 = vec![Poly::zero(); k];
        for i in 0..l {
            ntt_mult(&s1_ntt[i].coeff, &c_ntt.coeff, &mut cs1[i].coeff);
            ntt_inverse(&mut cs1[i].coeff);
        }
        for i in 0..k {
            ntt_mult(&s2_ntt[i].coeff, &c_ntt.coeff, &mut cs2[i].coeff);
            ntt_inverse(&mut cs2[i].coeff);
        }

        // z = y + cs1
        let mut z = vec![Poly::zero(); l];
        for i in 0..l {
            poly_add(&y[i], &cs1[i], &mut z[i]);
        }

        // r0 = LowBits(w - cs2)
        let mut r0 = vec![Poly::zero(); k];
        for i in 0..k {
            poly_sub(&w[i], &cs2[i], &mut r0[i]);
        }
        let r0 = vec_low_bits(&r0, gamma2);

        let z_max = vec_max_mod(&z);
        let r0_max = vec_max_signed(&r0);
        if z_max >= gamma1 - p.beta || r0_max >= gamma2 - p.beta {
            kappa += l as u32;
            continue;
        }

        // ct0 = NTT^-1(NTT(t0) ∘ c)
        let mut ct0 = vec![Poly::zero(); k];
        for i in 0..k {
            ntt_mult(&t0_ntt[i].coeff, &c_ntt.coeff, &mut ct0[i].coeff);
            ntt_inverse(&mut ct0[i].coeff);
        }
        // hint = MakeHint(-ct0, w - cs2) as implemented via (ct0, cs2, w)
        let mut hint = vec![Poly::zero(); k];
        for i in 0..k {
            for j in 0..hint[i].coeff.len() {
                hint[i].coeff[j] = make_hint(ct0[i].coeff[j], cs2[i].coeff[j], gamma2, w[i].coeff[j]);
            }
        }

        let ct0_max = vec_max_mod(&ct0);
        let h_ones = vec_count_ones(&hint);
        if ct0_max >= gamma2 || h_ones > p.omega as usize {
            kappa += l as u32;
            continue;
        }

        return Ok(sig_encode(&c_tilde, &z, &hint, gamma1, p.omega));
    }
}

/// FIPS 204 Algorithm 8 `ML-DSA.Verify_internal(pk, M', σ)`.
///
/// When `msg_is_mu` is true, `m_prime` is the 64-byte μ itself.
pub(crate) fn verify_internal(
    p: &Params,
    pub_exp: &ExpandedPub,
    m_prime: &[u8],
    sig: &[u8],
    msg_is_mu: bool,
) -> CryptoResult<bool> {
    let k = p.k;
    let l = p.l;
    let gamma2 = p.gamma2;

    let decoded = sig_decode(sig, p.gamma1, p.omega, k, l, p.c_tilde_len());
    let (c_tilde, z, hint) = match decoded {
        Some(d) => d,
        None => return Ok(false),
    };

    let mu = if msg_is_mu {
        if m_prime.len() != MU_BYTES {
            return Ok(false);
        }
        let mut mu = [0u8; MU_BYTES];
        mu.copy_from_slice(m_prime);
        mu
    } else {
        let mut mu = [0u8; MU_BYTES];
        shake256_xof(&[&pub_exp.tr, m_prime], &mut mu);
        mu
    };

    let c_ntt = sample_in_ball_ntt(&c_tilde, p.tau);

    // ct1 = NTT(c) ∘ NTT(t1·2^d)
    let ct1_ntt_base = scale_power2_round_ntt(&pub_exp.t1);
    let mut ct1_ntt = vec![Poly::zero(); k];
    for i in 0..k {
        ntt_mult(&ct1_ntt_base[i].coeff, &c_ntt.coeff, &mut ct1_ntt[i].coeff);
    }

    let z_max = vec_max_mod(&z);

    // w_approx = NTT^-1(A·NTT(z) - ct1)
    let a_ntt = expand_a(&pub_exp.rho, k, l);
    let mut z_ntt = z.clone();
    for poly in &mut z_ntt {
        ntt(&mut poly.coeff);
    }
    let mut w_approx = mat_vec_mul(&a_ntt, &z_ntt, k, l);
    for i in 0..k {
        let tmp = w_approx[i].clone();
        poly_sub(&tmp, &ct1_ntt[i], &mut w_approx[i]);
        ntt_inverse(&mut w_approx[i].coeff);
    }

    // w1' = UseHint(hint, w_approx)
    let mut w1 = vec![Poly::zero(); k];
    for i in 0..k {
        for j in 0..w1[i].coeff.len() {
            w1[i].coeff[j] = use_hint(hint[i].coeff[j], w_approx[i].coeff[j], gamma2);
        }
    }
    let w1_encoded = w1_encode(&w1, gamma2);

    let mut c_tilde2 = vec![0u8; p.c_tilde_len()];
    shake256_xof(&[&mu, &w1_encoded, &[]], &mut c_tilde2);

    Ok(z_max < p.gamma1 - p.beta && constant_time_eq(&c_tilde, &c_tilde2))
}

/// FIPS 204 §5.2 pure-signature message encoding:
/// `M' = 0x00 || len(ctx) || ctx || M`.
pub(crate) fn encode_pure(message: &[u8], ctx: &[u8]) -> CryptoResult<Vec<u8>> {
    if ctx.len() > super::params::MAX_CONTEXT_STRING_LEN {
        return Err(CryptoError::StrError("ml-dsa context string too long"));
    }
    let mut out = Vec::with_capacity(2 + ctx.len() + message.len());
    out.push(0u8);
    out.push(ctx.len() as u8);
    out.extend_from_slice(ctx);
    out.extend_from_slice(message);
    Ok(out)
}

/// Parse an encoded private key into expanded form (also derives `tr` by
/// recomputing the public key — see FIPS 204 Algorithm 25).
pub(crate) fn expand_priv(p: &Params, sk: &[u8]) -> CryptoResult<ExpandedPriv> {
    let (rho, k_seed, tr, s1, s2, t0) = sk_decode(sk, p.eta, p.l, p.k)
        .ok_or(CryptoError::StrError("ml-dsa invalid private key"))?;
    Ok(ExpandedPriv {
        rho,
        k_seed,
        tr,
        s1,
        s2,
        t0,
    })
}

/// Parse an encoded public key into expanded form; `tr = SHAKE256(pk, 64)`.
pub(crate) fn expand_pub(p: &Params, pk: &[u8]) -> CryptoResult<ExpandedPub> {
    let (rho, t1) =
        super::encode::pk_decode(pk, p.k).ok_or(CryptoError::StrError("ml-dsa invalid public key"))?;
    let mut tr = [0u8; TR_BYTES];
    shake256_xof(&[pk], &mut tr);
    Ok(ExpandedPub { rho, tr, t1 })
}
