//! Seed expansion / rejection sampling for ML-DSA (FIPS 204 §7.2).
//!
//! Rejection sampling is intentionally variable-time: the sampled values are
//! either public (`ExpandA`) or the discarded candidates leak nothing about
//! the accepted secret coefficients (see FIPS 204 §3.6.3).

use alloc::vec;
use alloc::vec::Vec;

use crate::core::{CoreRead, CoreWrite};
use crate::hash::sha3::{new_shake128, new_shake256};

use super::ntt::{mod_sub, ntt};
use super::params::{
    N, Q, ETA_4, GAMMA1_19, PRIV_SEED_BYTES, RHO_BYTES, RHO_PRIME_BYTES,
};
use super::poly::Poly;

/// FIPS 204 Algorithm 14 `CoeffFromThreeBytes`. Variable time (public input).
fn coeff_from_three_bytes(s: &[u8]) -> Option<u32> {
    let out = s[0] as u32 | ((s[1] as u32) << 8) | (((s[2] as u32) & 0x7f) << 16);
    if out < Q {
        Some(out)
    } else {
        None
    }
}

/// Constant-time-ish `n % 5` used by `CoeffFromHalfByte` for η = 2.
fn mod5(n: u32) -> u32 {
    n.wrapping_sub(5 * ((0x3335u32.wrapping_mul(n)) >> 16))
}

/// FIPS 204 Algorithm 15 `CoeffFromHalfByte` for η = 4.
fn coeff_from_nibble_4(nibble: u32) -> Option<u32> {
    if nibble < 9 {
        Some(mod_sub(4, nibble))
    } else {
        None
    }
}

/// FIPS 204 Algorithm 15 `CoeffFromHalfByte` for η = 2.
fn coeff_from_nibble_2(nibble: u32) -> Option<u32> {
    if nibble < 15 {
        Some(mod_sub(2, mod5(nibble)))
    } else {
        None
    }
}

/// FIPS 204 Algorithm 30 `RejNTTPoly` via SHAKE128. Variable time.
fn rej_ntt_poly(seed: &[u8]) -> Poly {
    let mut shake = new_shake128();
    shake.write_all(seed).expect("shake write");
    let mut out = Poly::zero();
    let mut j = 0;
    let mut block = [0u8; 168];
    loop {
        shake.read_exact(&mut block).expect("shake read");
        for b in block.chunks_exact(3) {
            if let Some(c) = coeff_from_three_bytes(b) {
                out.coeff[j] = c;
                j += 1;
                if j >= N {
                    return out;
                }
            }
        }
    }
}

/// FIPS 204 Algorithm 31 `RejBoundedPoly` via SHAKE256. Variable time.
fn rej_bounded_poly(eta: u32, seed: &[u8]) -> Poly {
    let mut shake = new_shake256();
    shake.write_all(seed).expect("shake write");
    let mut out = Poly::zero();
    let mut j = 0;
    let mut block = [0u8; 136];
    loop {
        shake.read_exact(&mut block).expect("shake read");
        for &byte in &block {
            for nibble in [byte & 0x0f, byte >> 4] {
                let cand = if eta == ETA_4 {
                    coeff_from_nibble_4(nibble as u32)
                } else {
                    coeff_from_nibble_2(nibble as u32)
                };
                if let Some(c) = cand {
                    out.coeff[j] = c;
                    j += 1;
                    if j >= N {
                        return out;
                    }
                }
            }
        }
    }
}

/// FIPS 204 Algorithm 32 `ExpandA`: sample the `k × l` matrix `A` in NTT
/// domain from the public seed `rho`.
pub(crate) fn expand_a(rho: &[u8; RHO_BYTES], k: usize, l: usize) -> Vec<Poly> {
    let mut derived = [0u8; RHO_BYTES + 2];
    derived[..RHO_BYTES].copy_from_slice(rho);
    let mut out = Vec::with_capacity(k * l);
    for i in 0..k {
        for j in 0..l {
            derived[RHO_BYTES] = j as u8;
            derived[RHO_BYTES + 1] = i as u8;
            out.push(rej_ntt_poly(&derived));
        }
    }
    out
}

/// FIPS 204 Algorithm 33 `ExpandS`: sample short secret vectors `s1` (length
/// `l`) and `s2` (length `k`).
pub(crate) fn expand_s(
    seed: &[u8; PRIV_SEED_BYTES],
    eta: u32,
    l: usize,
    k: usize,
) -> (Vec<Poly>, Vec<Poly>) {
    let mut derived = [0u8; PRIV_SEED_BYTES + 2];
    derived[..PRIV_SEED_BYTES].copy_from_slice(seed);
    let mut counter: u16 = 0;
    let mut next = || {
        derived[PRIV_SEED_BYTES] = (counter & 0xff) as u8;
        derived[PRIV_SEED_BYTES + 1] = (counter >> 8) as u8;
        counter += 1;
        rej_bounded_poly(eta, &derived)
    };
    let s1: Vec<Poly> = (0..l).map(|_| next()).collect();
    let s2: Vec<Poly> = (0..k).map(|_| next()).collect();
    (s1, s2)
}

/// FIPS 204 Algorithm 34 `ExpandMask` steps 4–5: sample one polynomial `y`
/// with coefficients in `(-gamma1, gamma1]` from `seed` (which already embeds
/// the nonce index).
pub(crate) fn expand_mask(seed: &[u8], gamma1: u32) -> Poly {
    let buf_len = if gamma1 == GAMMA1_19 { 32 * 20 } else { 32 * 18 };
    let mut buf = vec![0u8; buf_len];
    let mut shake = new_shake256();
    shake.write_all(seed).expect("shake write");
    shake.read_exact(&mut buf).expect("shake read");
    let poly = decode_expand_mask(&buf, gamma1);
    poly
}

/// Unpack a mask polynomial from `buf` (18 or 20 bits per coefficient).
fn decode_expand_mask(buf: &[u8], gamma1: u32) -> Poly {
    let mut out = Poly::zero();
    if gamma1 == GAMMA1_19 {
        // 20 bits per coefficient, 4 coefficients per 10 bytes.
        const RANGE: u32 = 1 << 19;
        const MASK: u32 = (1 << 20) - 1;
        for (i, chunk) in buf.chunks_exact(10).enumerate() {
            let a1 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let a2 = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            let a3 = u16::from_le_bytes([chunk[8], chunk[9]]) as u32;
            let base = i * 4;
            out.coeff[base] = mod_sub(RANGE, a1 & MASK);
            out.coeff[base + 1] = mod_sub(RANGE, (a1 >> 20) | ((a2 & 0xff) << 12));
            out.coeff[base + 2] = mod_sub(RANGE, (a2 >> 8) & MASK);
            out.coeff[base + 3] = mod_sub(RANGE, (a2 >> 28) | (a3 << 4));
        }
    } else {
        // 18 bits per coefficient, 4 coefficients per 9 bytes.
        const RANGE: u32 = 1 << 17;
        const MASK: u32 = (1 << 18) - 1;
        for (i, chunk) in buf.chunks_exact(9).enumerate() {
            let a1 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let a2 = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            let a3 = chunk[8] as u32;
            let base = i * 4;
            out.coeff[base] = mod_sub(RANGE, a1 & MASK);
            out.coeff[base + 1] = mod_sub(RANGE, (a1 >> 18) | ((a2 & 0xf) << 14));
            out.coeff[base + 2] = mod_sub(RANGE, (a2 >> 4) & MASK);
            out.coeff[base + 3] = mod_sub(RANGE, (a2 >> 22) | (a3 << 10));
        }
    }
    out
}

/// Expand the whole mask vector `y` for one signing attempt with nonce
/// `kappa` (FIPS 204 Algorithm 34).
pub(crate) fn expand_mask_vector(
    rho_prime: &[u8; RHO_PRIME_BYTES],
    kappa: u32,
    gamma1: u32,
    l: usize,
) -> Vec<Poly> {
    let mut derived = [0u8; RHO_PRIME_BYTES + 2];
    derived[..RHO_PRIME_BYTES].copy_from_slice(rho_prime);
    (0..l)
        .map(|i| {
            let index = kappa + i as u32;
            derived[RHO_PRIME_BYTES] = (index & 0xff) as u8;
            derived[RHO_PRIME_BYTES + 1] = ((index >> 8) & 0xff) as u8;
            expand_mask(&derived, gamma1)
        })
        .collect()
}

/// FIPS 204 Algorithm 29 `SampleInBall`: polynomial with `tau` coefficients
/// in `{q-1, 0, 1}` (i.e. signed `{−1, 0, 1}`).
///
/// Variable time (the challenge is public once the signature is produced).
pub(crate) fn sample_in_ball(seed: &[u8], tau: u32) -> Poly {
    let mut shake = new_shake256();
    shake.write_all(seed).expect("shake write");
    let mut block = [0u8; 136];
    shake.read_exact(&mut block).expect("shake read");

    let mut signs = u64::from_le_bytes(block[..8].try_into().unwrap());
    let mut offset = 8usize;
    let mut out = Poly::zero();

    for end in (256 - tau as usize)..256 {
        // Rejection-sample an index in 0..=end.
        let index = loop {
            if offset == block.len() {
                shake.read_exact(&mut block).expect("shake read");
                offset = 0;
            }
            let index = block[offset] as usize;
            offset += 1;
            if index <= end {
                break index;
            }
        };
        // In-place Fisher-Yates swap with the current end position.
        out.coeff[end] = out.coeff[index];
        out.coeff[index] = mod_sub(1, 2 * (signs as u32 & 1));
        signs >>= 1;
    }
    out
}

/// Sample the challenge polynomial and transform it to NTT domain.
pub(crate) fn sample_in_ball_ntt(seed: &[u8], tau: u32) -> Poly {
    let mut c = sample_in_ball(seed, tau);
    ntt(&mut c.coeff);
    c
}
