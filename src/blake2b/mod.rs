mod generic;
mod noasm;

mod variable;
pub use variable::*;

#[cfg(test)]
mod tests;

use crate::core::CoreWrite;
use crate::error::{CryptoError, CryptoResult};
use crate::hash::{Hash, HashUser, HashVariable};
use noasm::hash_blocks;

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

pub(crate) const BLOCK_SIZE: usize = 128;
pub(crate) const SIZE: usize = 64;
pub(crate) const SIZE384: usize = 48;
pub(crate) const SIZE256: usize = 32;

pub struct Blake2b<const N: usize>(Blake2bVariable);

impl<const N: usize> Blake2b<N> {
    fn new(key: Option<&[u8]>) -> CryptoResult<Blake2b<N>> {
        Ok(Self(Blake2bVariable::new(key, N)?))
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> crate::hmac::Marshalable for Blake2b<N> {
    fn marshal_size(&self) -> usize {
        self.0.marshal_size()
    }

    fn marshal_into(&self, out: &mut [u8]) -> CryptoResult<usize> {
        self.0.marshal_into(out)
    }

    fn unmarshal_binary(&mut self, b: &[u8]) -> CryptoResult<()> {
        self.0.unmarshal_binary(b)
    }
}

impl<const N: usize> HashUser for Blake2b<N> {
    fn reset(&mut self) {
        self.0.reset()
    }

    fn size(&self) -> usize {
        N
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }
}

impl<const N: usize> CoreWrite for Blake2b<N> {
    fn write(&mut self, p: &[u8]) -> CryptoResult<usize> {
        self.0.write(p)
    }

    fn flush(&mut self) -> CryptoResult<()> {
        self.0.flush()
    }
}

impl<const N: usize> Hash<N> for Blake2b<N> {
    fn sum(&mut self) -> [u8; N] {
        let mut hash = [0u8; SIZE];
        let s = self.0.sum(&mut hash);
        debug_assert_eq!(s, N);

        let mut ret = [0u8; N];
        ret.copy_from_slice(&hash[..N]);
        ret
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
            pub fn $name(key: Option<&[u8]>) -> CryptoResult<Blake2b<$len>> {
                Blake2b::new(key)
            }
        }
    };
}

impl_new_for!(new512, 64, "Blake2b");
impl_new_for!(new384, 48, "Blake2b");
impl_new_for!(new256, 32, "Blake2b");

macro_rules! impl_sum_for {
    ($name:ident, $fn:expr, $len:expr, $x:literal) => {
        paste::paste! {
            #[doc = "Compute the " $x " checksum of the input."]
            pub fn $name(data: &[u8]) -> [u8; $len] {
                let mut digest = Blake2b::<$len>::new(None).unwrap();
                digest.write_all(&data).unwrap();
                digest.sum()
            }
        }
    };
}

impl_sum_for!(sum512, new512, SIZE, "BLAKE2B-512");
impl_sum_for!(sum384, new384, SIZE384, "BLAKE2B-384");
impl_sum_for!(sum256, new256, SIZE256, "BLAKE2B-256");
