//! RSA prime generation, following OpenSSL `crypto/bn/bn_prime.c`
//! (`BN_generate_prime_ex2`) and the RSA key generator's checks:
//!
//! * candidates have their top two bits set and are odd,
//! * `gcd(candidate - 1, e) == 1`,
//! * trial division by all small primes below ~17864,
//! * Miller-Rabin with 64 rounds (128 above 2048 bits) — the modern
//!   `bn_mr_min_checks` default.

use super::Rng;
use crate::bn::Bn;
use crate::error::{CryptoError, CryptoResult};
use alloc::vec::Vec;

/// Miller-Rabin rounds per `bn_mr_min_checks`.
fn mr_rounds(bits: usize) -> usize {
    if bits > 2048 {
        128
    } else {
        64
    }
}

/// All primes below 17864 (OpenSSL's trial-division table size), computed
/// with a simple sieve.
fn small_primes() -> Vec<u64> {
    const LIMIT: usize = 17864;
    let mut sieve = alloc::vec![true; LIMIT];
    let mut out = Vec::new();
    for i in 2..LIMIT {
        if sieve[i] {
            out.push(i as u64);
            let mut j = i * i;
            while j < LIMIT {
                sieve[j] = false;
                j += i;
            }
        }
    }
    out
}

/// Generate a `bits`-bit probable prime coprime to `e` (i.e. with
/// `gcd(p - 1, e) == 1`).
pub fn generate_prime(bits: usize, e: u64, rng: &mut impl Rng) -> CryptoResult<Bn> {
    if bits < 128 {
        return Err(CryptoError::StrError("rsa: prime too small"));
    }
    let primes = small_primes();

    loop {
        // Random candidate: top two bits set, bottom bit odd
        // (BN_RAND_TOP_TWO | BN_RAND_BOTTOM_ODD).
        let mut bytes = alloc::vec![0u8; bits.div_ceil(8)];
        rng.fill_bytes(&mut bytes);
        let extra = bytes.len() * 8 - bits;
        if extra > 0 {
            bytes[0] &= 0xff >> extra;
        }
        bytes[0] |= 0xc0 >> extra;
        *bytes.last_mut().unwrap() |= 1;
        let cand = Bn::from_be_bytes(&bytes);

        // The RSA exponent must be invertible modulo p - 1.
        let cand1 = cand.sub(&Bn::one())?;
        if cand1.rem_small(e) == 0 {
            continue;
        }

        // Cheap trial division before the expensive test.
        if primes.iter().any(|&p| cand.rem_small(p) == 0) {
            continue;
        }

        if is_probable_prime(&cand, mr_rounds(bits), rng)? {
            return Ok(cand);
        }
    }
}

/// Miller-Rabin probabilistic primality test (FIPS 186-4 C.3.1).
pub fn is_probable_prime(n: &Bn, rounds: usize, rng: &mut impl Rng) -> CryptoResult<bool> {
    if n.lt(&Bn::from_u64(3)) || n.is_even() {
        return Ok(false);
    }

    let n1 = n.sub(&Bn::one())?;
    // n1 = 2^s * d with d odd.
    let mut s = 0usize;
    let mut d = n1.clone();
    while d.is_even() {
        d.shr1();
        s += 1;
    }
    // Witness range: [2, n - 2].
    let range = n1.sub(&Bn::one())?.sub(&Bn::one())?; // n - 3

    'rounds: for _ in 0..rounds {
        let mut buf = alloc::vec![0u8; n.byte_len() + 8];
        rng.fill_bytes(&mut buf);
        let witness = Bn::from_be_bytes(&buf)
            .modulus(&range)
            .add(&Bn::from_u64(2));

        // Run the whole exponentiation in Montgomery form so the
        // squarings avoid general division.
        let mont = crate::bn::Montgomery::new(n)?;
        let one_m = mont.to_mont(&Bn::one());
        let n1_m = mont.to_mont(&n1);
        let mut x = mont.pow(&mont.to_mont(&witness), &d);
        if x == one_m || x == n1_m {
            continue;
        }
        for _ in 0..s.saturating_sub(1) {
            x = mont.mul(&x, &x);
            if x == n1_m {
                continue 'rounds;
            }
            if x == one_m {
                return Ok(false);
            }
        }
        return Ok(false);
    }
    Ok(true)
}
