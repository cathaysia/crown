use crate::core::CoreRead;
use crate::error::{CryptoError, CryptoResult};
use crate::hmac::HMAC;

use super::*;
use alloc::boxed::Box;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Md4,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Blake2b256,
    Blake2b384,
    Blake2b512,
    Blake2s128,
    Blake2s256,
    Blake2s,
    Shake128,
    Shake256,
}

impl core::str::FromStr for HashAlgorithm {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "md4" | "md4sum" => Ok(Self::Md4),
            "md5" | "md5sum" => Ok(Self::Md5),
            "sha1" => Ok(Self::Sha1),
            "sha224" => Ok(Self::Sha224),
            "sha256" => Ok(Self::Sha256),
            "sha384" => Ok(Self::Sha384),
            "sha512" => Ok(Self::Sha512),
            "sha512-224" => Ok(Self::Sha512_224),
            "sha512-256" => Ok(Self::Sha512_256),
            "sha3-224" => Ok(Self::Sha3_224),
            "sha3-256" => Ok(Self::Sha3_256),
            "sha3-384" => Ok(Self::Sha3_384),
            "sha3-512" => Ok(Self::Sha3_512),
            "blake2b-256" => Ok(Self::Blake2b256),
            "blake2b-384" => Ok(Self::Blake2b384),
            "blake2b-512" => Ok(Self::Blake2b512),
            "blake2s-128" => Ok(Self::Blake2s128),
            "blake2s-256" => Ok(Self::Blake2s256),
            "blake2s" => Ok(Self::Blake2s),
            "shake128" => Ok(Self::Shake128),
            "shake256" => Ok(Self::Shake256),
            _ => Err(CryptoError::InvalidHasher),
        }
    }
}

trait ErasedHashInner: CoreWrite + CoreRead + HashUser {
    fn sum(&mut self) -> Vec<u8>;
}

pub struct MessageDigest(Box<dyn ErasedHashInner>);

impl MessageDigest {
    fn new_impl<T, const N: usize>(h: T) -> Self
    where
        T: Hash<N> + 'static,
    {
        struct Wrapper<T, const N: usize> {
            hasher: T,
            output: Option<Vec<u8>>,
            read_pos: usize,
        }

        impl<T, const N: usize> CoreWrite for Wrapper<T, N>
        where
            T: Hash<N>,
        {
            fn write(&mut self, buf: &[u8]) -> CryptoResult<usize> {
                self.hasher.write(buf)
            }

            fn flush(&mut self) -> CryptoResult<()> {
                self.hasher.flush()
            }
        }

        impl<T, const N: usize> CoreRead for Wrapper<T, N>
        where
            T: Hash<N>,
        {
            fn read(&mut self, buf: &mut [u8]) -> CryptoResult<usize> {
                if self.output.is_none() {
                    self.output = Some(self.hasher.sum().to_vec());
                    self.read_pos = 0;
                }

                let output = self.output.as_ref().unwrap();
                let remaining = output.len().saturating_sub(self.read_pos);
                let to_read = buf.len().min(remaining);

                if to_read == 0 {
                    return Ok(0);
                }

                buf[..to_read].copy_from_slice(&output[self.read_pos..self.read_pos + to_read]);
                self.read_pos += to_read;
                Ok(to_read)
            }
        }

        impl<T, const N: usize> HashUser for Wrapper<T, N>
        where
            T: Hash<N>,
        {
            fn reset(&mut self) {
                self.hasher.reset();
                self.output = None;
                self.read_pos = 0;
            }

            fn size(&self) -> usize {
                self.hasher.size()
            }

            fn block_size(&self) -> usize {
                self.hasher.block_size()
            }
        }

        impl<T, const N: usize> ErasedHashInner for Wrapper<T, N>
        where
            T: Hash<N>,
        {
            fn sum(&mut self) -> Vec<u8> {
                self.hasher.sum().to_vec()
            }
        }

        Self(Box::new(Wrapper {
            hasher: h,
            output: None,
            read_pos: 0,
        }))
    }

    fn new_impl_variant<T>(h: T) -> Self
    where
        T: CoreWrite + CoreRead + HashUser + 'static,
    {
        struct VariantWrapper<T>(T);

        impl<T> CoreWrite for VariantWrapper<T>
        where
            T: CoreWrite + CoreRead + HashUser,
        {
            fn write(&mut self, buf: &[u8]) -> CryptoResult<usize> {
                self.0.write(buf)
            }

            fn flush(&mut self) -> CryptoResult<()> {
                self.0.flush()
            }
        }

        impl<T> CoreRead for VariantWrapper<T>
        where
            T: CoreWrite + CoreRead + HashUser,
        {
            fn read(&mut self, buf: &mut [u8]) -> CryptoResult<usize> {
                self.0.read(buf)
            }
        }

        impl<T> HashUser for VariantWrapper<T>
        where
            T: CoreWrite + CoreRead + HashUser,
        {
            fn reset(&mut self) {
                self.0.reset()
            }

            fn size(&self) -> usize {
                0
            }

            fn block_size(&self) -> usize {
                self.0.block_size()
            }
        }

        impl<T> ErasedHashInner for VariantWrapper<T>
        where
            T: CoreWrite + CoreRead + HashUser,
        {
            fn sum(&mut self) -> Vec<u8> {
                vec![]
            }
        }

        Self(Box::new(VariantWrapper(h)))
    }

    pub fn new(algorithm: HashAlgorithm, key: Option<&[u8]>) -> CryptoResult<Self> {
        macro_rules! hash_match {
            (
                $(($variant:ident, $hash_fn:expr, $type:ident)),* $(,)?
            ) => {
                match algorithm {
                    $(
                        HashAlgorithm::$variant => {
                            hash_match!(@create $hash_fn, $type, key)
                        }
                    )*
                }
            };
            (@create $hash_fn:expr, normal, $key:expr) => {
                if let Some(key) = $key {
                    Self::new_impl(HMAC::new($hash_fn, key))
                } else {
                    Self::new_impl($hash_fn())
                }
            };
            (@create $hash_fn:expr, blake, $key:expr) => {
                Self::new_impl($hash_fn($key)?)
            };
            (@create $hash_fn:expr, shake, $key:expr) => {
                Self::new_impl_variant($hash_fn())
            };
        }

        Ok(hash_match!(
            (Md4, crate::md4::new_md4, normal),
            (Md5, crate::md5::new_md5, normal),
            (Sha1, crate::sha1::new, normal),
            (Sha224, crate::sha256::new224, normal),
            (Sha256, crate::sha256::new256, normal),
            (Sha384, crate::sha512::new384, normal),
            (Sha512, crate::sha512::new512, normal),
            (Sha512_224, crate::sha512::new512_224, normal),
            (Sha512_256, crate::sha512::new512_256, normal),
            (Sha3_224, crate::sha3::new224, normal),
            (Sha3_256, crate::sha3::new256, normal),
            (Sha3_384, crate::sha3::new384, normal),
            (Sha3_512, crate::sha3::new512, normal),
            (Blake2b256, crate::blake2b::new256, blake),
            (Blake2b384, crate::blake2b::new384, blake),
            (Blake2b512, crate::blake2b::new512, blake),
            (Blake2s128, crate::blake2s::new128, blake),
            (Blake2s256, crate::blake2s::new256, blake),
            (Blake2s, crate::sha3::new512, normal),
            (Shake128, crate::sha3::new_shake128, shake),
            (Shake256, crate::sha3::new_shake256, shake),
        ))
    }

    pub fn sum(&mut self) -> Vec<u8> {
        self.0.sum()
    }
}

impl CoreRead for MessageDigest {
    fn read(&mut self, buf: &mut [u8]) -> CryptoResult<usize> {
        self.0.read(buf)
    }
}

impl CoreWrite for MessageDigest {
    fn write(&mut self, buf: &[u8]) -> CryptoResult<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> CryptoResult<()> {
        self.0.flush()
    }
}

impl HashUser for MessageDigest {
    fn reset(&mut self) {
        self.0.reset()
    }

    fn size(&self) -> usize {
        self.0.size()
    }

    fn block_size(&self) -> usize {
        self.0.block_size()
    }
}
