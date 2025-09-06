//! Module [sha3](crate::sha3) implements the [SHA-3](https://en.wikipedia.org/wiki/SHA-3)
//! fixed-output-length hash functions and the SHAKE variable-output-length functions
//! defined by [FIPS 202], as well as the cSHAKE extendable-output-length
//! functions defined by [SP 800-185].
//!
//! [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
//! [SP 800-185]: https://doi.org/10.6028/NIST.SP.800-185
//!
//!

#![allow(dead_code)]
mod digest;
mod keccakf;

#[cfg(feature = "alloc")]
mod shake;
#[cfg(feature = "alloc")]
pub use shake::*;

mod noasm;
use crate::core::CoreWrite;

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

macro_rules! impl_new_for {
    ($name:ident, $output_len:expr, $rate_len:expr, $len3:expr, $kind:literal) => {
        paste::paste! {
            #[doc =
                "Create a new [Hash] computing the " $kind " checksum.\n\n"
                "The Hash also implements [Marshalable](crate::hmac::Marshalable)"
                "to marshal and unmarshal the internal state of the hash."
            ]
            pub fn $name() -> Sha3<$output_len> {
                Sha3 {
                    a: [0; 200],
                    n: 0,
                    rate: [<RATE_K $rate_len>],
                    dsbyte: DSBYTE_SHA3,
                    state: digest::SpongeDirection::Absorbing,
                }
            }

            #[doc="Compute the SHA-" $output_len " checksum of the input."]
            pub fn [<sum $len3>](data: &[u8]) -> [u8; $output_len] {
                let mut h = $name();
                h.write_all(data).unwrap();

                h.sum()
            }
        }
    };
}

impl_new_for!(new224, 28, 448, 224, "SHA3-224");
impl_new_for!(new256, 32, 512, 256, "SHA3-256");
impl_new_for!(new384, 48, 768, 384, "SHA3-384");
impl_new_for!(new512, 64, 1024, 512, "SHA3-512");

/// Create a new [Hash] computing the legacy, non-standard
/// Keccak-256 hash.
pub fn new_legacy_keccak256() -> Sha3<32> {
    Sha3 {
        a: [0; 200],
        n: 0,
        rate: RATE_K512,
        dsbyte: DSBYTE_KECCAK,
        state: digest::SpongeDirection::Absorbing,
    }
}

/// Create a new [Hash] computing the legacy, non-standard
/// Keccak-512 hash.
pub fn new_legacy_keccak512() -> Sha3<64> {
    Sha3 {
        a: [0; 200],
        n: 0,
        rate: RATE_K1024,
        dsbyte: DSBYTE_KECCAK,
        state: digest::SpongeDirection::Absorbing,
    }
}

/// Create a new [Hash] computing the SHAKE128 XOF checksum.
///
/// The Hash also implements Marshalableto marshal and unmarshal the internal state of the hash.
#[cfg(feature = "alloc")]
pub fn new_shake128() -> Shake<32> {
    Shake {
        d: Sha3 {
            a: [0; 200],
            n: 0,
            rate: RATE_K256,
            dsbyte: DSBYTE_SHAKE,
            state: digest::SpongeDirection::Absorbing,
        },
        init_block: alloc::vec::Vec::new(),
    }
}

/// Create a new [Hash] computing the SHAKE256 XOF checksum.
///
/// The Hash also implements Marshalableto marshal and unmarshal the internal state of the hash.
#[cfg(feature = "alloc")]
pub fn new_shake256() -> Shake<64> {
    Shake {
        d: Sha3 {
            a: [0; 200],
            n: 0,
            rate: RATE_K512,
            dsbyte: DSBYTE_SHAKE,
            state: digest::SpongeDirection::Absorbing,
        },
        init_block: alloc::vec::Vec::new(),
    }
}

/// Creates a [Hash] computing the cSHAKE128 XOF checksum.
///
/// N is used to define functions based on cSHAKE, it can be empty when plain
/// cSHAKE is desired. S is a customization byte string used for domain
/// separation. When N and S are both empty, this is equivalent to NewShake128.
#[cfg(feature = "alloc")]
pub fn new_cshake128(n: &[u8], s: &[u8]) -> Shake<32> {
    if n.is_empty() && s.is_empty() {
        return new_shake128();
    }
    new_cshake(n, s, RATE_K256, DSBYTE_CSHAKE)
}

/// Creates a [Hash] computing the cSHAKE256 XOF checksum.
///
/// N is used to define functions based on cSHAKE, it can be empty when plain
/// cSHAKE is desired. S is a customization byte string used for domain
/// separation. When N and S are both empty, this is equivalent to NewShake256.
#[cfg(feature = "alloc")]
pub fn new_cshake256(n: &[u8], s: &[u8]) -> Shake<64> {
    if n.is_empty() && s.is_empty() {
        return new_shake256();
    }
    new_cshake(n, s, RATE_K512, DSBYTE_CSHAKE)
}

macro_rules! impl_shakesum_for {
    ($len:literal) => {
        paste::paste! {
            #[doc="Compute the Shake-" $len " checksum of the input."]
            #[cfg(feature = "alloc")]
            pub fn [<sum_shake $len>](data: &[u8]) -> [u8; $len / 8*2] {
                let mut h = [<new_ shake $len>]();
                h.write_all(data).unwrap();

                let sum = h.sum();

                sum
            }
        }
    };
}

impl_shakesum_for!(128);
impl_shakesum_for!(256);
