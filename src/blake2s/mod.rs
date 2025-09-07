mod generic;
mod noasm;
mod variable;

#[cfg(test)]
mod tests;

use crate::blake2s::variable::Blake2sVariable;
use crate::core::CoreWrite;
use crate::error::{CryptoError, CryptoResult};
use crate::hash::{Hash, HashUser, HashVariable};
use crate::utils::copy;

pub use noasm::hash_blocks;

// Constants
pub const BLOCK_SIZE: usize = 64;
pub const SIZE: usize = 32;
pub const SIZE_128: usize = 16;

// Initialization vector
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub struct Blake2s<const N: usize>(Blake2sVariable);

impl<const N: usize> HashUser for Blake2s<N> {
    fn reset(&mut self) {
        self.0.reset_impl();
    }

    fn size(&self) -> usize {
        N
    }

    fn block_size(&self) -> usize {
        self.0.block_size()
    }
}

impl<const N: usize> CoreWrite for Blake2s<N> {
    fn write(&mut self, p: &[u8]) -> CryptoResult<usize> {
        self.0.write(p)
    }

    fn flush(&mut self) -> CryptoResult<()> {
        self.0.flush()
    }
}

impl<const N: usize> Hash<N> for Blake2s<N> {
    fn sum(&mut self) -> [u8; N] {
        let mut v = [0u8; N];
        self.0.sum(&mut v);
        v
    }
}

macro_rules! impl_new_for {
    ($name:ident, $len:expr, $x:literal) => {
        paste::paste! {
            #[doc =
                "Create a new [Hash] computing the " $x " checksum.\n\n"
                "The Hash also implements [Marshalable](crate::hmac::Marshalable)"
                "to marshal and unmarshal the internal state of the hash."
            ]
            pub fn $name(key: Option<&[u8]>) -> CryptoResult<Blake2s<$len>> {
                Ok(Blake2s(Blake2sVariable::new(key, $len)?))
            }
        }
    };
}

impl_new_for!(new128, 16, "Blake2s");
impl_new_for!(new256, 32, "Blake2s");

macro_rules! impl_sum_for {
    ($name:ident, $fn:expr, $len:expr, $x:literal) => {
        paste::paste! {
            #[doc = "Compute the " $x " checksum of the input."]
            pub fn $name(data: &[u8]) -> [u8; $len] {
                let mut digest = Blake2s::<$len>(Blake2sVariable::new(None, $len).unwrap());
                digest.write_all(&data).unwrap();
                digest.sum()
            }
        }
    };
}

impl_sum_for!(sum128, new128, 16, "BLAKE2s-128");
impl_sum_for!(sum256, new256, 32, "BLAKE2s-256");
