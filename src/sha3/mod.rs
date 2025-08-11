//! Module sha3 implements the SHA-3 fixed-output-length hash functions and
//! the SHAKE variable-output-length functions defined by [FIPS 202], as well as
//! the cSHAKE extendable-output-length functions defined by [SP 800-185].
//!
//! [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
//! [SP 800-185]: https://doi.org/10.6028/NIST.SP.800-185

#![allow(dead_code)]
mod digest;
mod keccakf;

mod shake;
pub use shake::*;

mod noasm;
use std::io::Write;

use noasm::*;

#[cfg(test)]
mod tests;

pub use digest::Sha3;

use crate::hash::Hash;

// Domain separation bytes
const DSBYTE_SHA3: u8 = 0b00000110;
const DSBYTE_KECCAK: u8 = 0b00000001;
const DSBYTE_SHAKE: u8 = 0b00011111;
const DSBYTE_CSHAKE: u8 = 0b00000100;

// rateK[c] is the rate in bytes for Keccak[c] where c is the capacity in
// bits. Given the sponge size is 1600 bits, the rate is 1600 - c bits.
const RATE_K256: usize = (1600 - 256) / 8;
const RATE_K448: usize = (1600 - 448) / 8;
const RATE_K512: usize = (1600 - 512) / 8;
const RATE_K768: usize = (1600 - 768) / 8;
const RATE_K1024: usize = (1600 - 1024) / 8;

macro_rules! impl_sum_for {
    ($len:literal) => {
        paste::paste! {
            pub fn [<sum $len>](data: &[u8]) -> [u8; $len / 8] {
                let mut h = [<new $len>]();
                h.write_all(data).unwrap();

                let sum = h.sum(&[]);

                sum.try_into().unwrap()
            }
        }
    };
}

macro_rules! impl_shakesum_for {
    ($len:literal) => {
        paste::paste! {
            pub fn [<sum_shake_ $len>](data: &[u8]) -> [u8; $len / 8] {
                let mut h = shake::[<new_ shake $len>]();
                h.write_all(data).unwrap();

                let sum = h.sum(&[]);

                sum.try_into().unwrap()
            }
        }
    };
}

impl_sum_for!(256);
impl_sum_for!(224);
impl_sum_for!(384);
impl_sum_for!(512);

impl_shakesum_for!(128);
impl_shakesum_for!(256);

/// New224 returns a new Digest computing the SHA3-224 hash.
pub fn new224() -> Sha3 {
    Sha3 {
        a: [0; 200],
        n: 0,
        rate: RATE_K448,
        dsbyte: DSBYTE_SHA3,
        output_len: 28,
        state: digest::SpongeDirection::Absorbing,
    }
}

/// New256 returns a new Digest computing the SHA3-256 hash.
pub fn new256() -> Sha3 {
    Sha3 {
        a: [0; 200],
        n: 0,
        rate: RATE_K512,
        dsbyte: DSBYTE_SHA3,
        output_len: 32,
        state: digest::SpongeDirection::Absorbing,
    }
}

/// New384 returns a new Digest computing the SHA3-384 hash.
pub fn new384() -> Sha3 {
    Sha3 {
        a: [0; 200],
        n: 0,
        rate: RATE_K768,
        dsbyte: DSBYTE_SHA3,
        output_len: 48,
        state: digest::SpongeDirection::Absorbing,
    }
}

/// New512 returns a new Digest computing the SHA3-512 hash.
pub fn new512() -> Sha3 {
    Sha3 {
        a: [0; 200],
        n: 0,
        rate: RATE_K1024,
        dsbyte: DSBYTE_SHA3,
        output_len: 64,
        state: digest::SpongeDirection::Absorbing,
    }
}

/// NewLegacyKeccak256 returns a new Digest computing the legacy, non-standard
/// Keccak-256 hash.
pub fn new_legacy_keccak256() -> Sha3 {
    Sha3 {
        a: [0; 200],
        n: 0,
        rate: RATE_K512,
        dsbyte: DSBYTE_KECCAK,
        output_len: 32,
        state: digest::SpongeDirection::Absorbing,
    }
}

/// NewLegacyKeccak512 returns a new Digest computing the legacy, non-standard
/// Keccak-512 hash.
pub fn new_legacy_keccak512() -> Sha3 {
    Sha3 {
        a: [0; 200],
        n: 0,
        rate: RATE_K1024,
        dsbyte: DSBYTE_KECCAK,
        output_len: 64,
        state: digest::SpongeDirection::Absorbing,
    }
}
