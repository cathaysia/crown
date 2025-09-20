use crate::core::{CoreRead, CoreWrite};
use crate::error::CryptoResult;
use crate::hash::Hash;
use crate::hash::HashUser;
use crate::hmac::HMAC;

use alloc::boxed::Box;
use alloc::vec::Vec;

macro_rules! impl_hash_methods {
    (
        normal: [$($normal:ident, $hash_fn:expr),* $(,)?],
        variant: [$($variant:ident, $variant_fn:expr),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                pub fn [<new_ $normal:lower>]() -> CryptoResult<Self> {
                    Ok(Self::new_impl($hash_fn()))
                }

                pub fn [<new_ $normal:lower _hmac>](key: &[u8]) -> CryptoResult<Self> {
                    Ok(Self::new_impl(HMAC::new($hash_fn, key)))
                }
            }
        )*
        $(
            paste::paste! {
                pub fn [<new_ $variant:lower>](key: Option<&[u8]>, key_len: usize) -> CryptoResult<Self> {
                    Ok(Self::new_impl_variant($variant_fn(key, key_len)?))
                }
            }
        )*
    };
}

trait EvpHashInner: CoreWrite + CoreRead + HashUser {
    fn sum(&mut self) -> Vec<u8>;
}

pub struct EvpHash(Box<dyn EvpHashInner>);

impl EvpHash {
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

        impl<T, const N: usize> EvpHashInner for Wrapper<T, N>
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
                self.0.size()
            }

            fn block_size(&self) -> usize {
                self.0.block_size()
            }
        }

        impl<T> EvpHashInner for VariantWrapper<T>
        where
            T: CoreWrite + CoreRead + HashUser,
        {
            fn sum(&mut self) -> Vec<u8> {
                let len = self.size();
                let mut buf = vec![0; len];
                self.0.read(&mut buf).unwrap();
                buf
            }
        }

        Self(Box::new(VariantWrapper(h)))
    }

    impl_hash_methods!(
        normal: [
            md2, crate::md2::new_md2,
            md4, crate::md4::new_md4,
            md5, crate::md5::new_md5,
            sha1, crate::sha1::new,
            sha224, crate::sha256::new224,
            sha256, crate::sha256::new256,
            sha384, crate::sha512::new384,
            sha512, crate::sha512::new512,
            sha512_224, crate::sha512::new512_224,
            sha512_256, crate::sha512::new512_256,
            sha3_224, crate::sha3::new224,
            sha3_256, crate::sha3::new256,
            sha3_384, crate::sha3::new384,
            sha3_512, crate::sha3::new512,
            shake128, crate::sha3::new_shake128,
            shake256, crate::sha3::new_shake256,
        ],
        variant: [
            blake2s, crate::blake2s::Blake2sVariable::new,
            blake2b, crate::blake2b::Blake2bVariable::new,
        ],
    );

    pub fn sum(&mut self) -> Vec<u8> {
        self.0.sum()
    }
}

impl CoreRead for EvpHash {
    fn read(&mut self, buf: &mut [u8]) -> CryptoResult<usize> {
        self.0.read(buf)
    }
}

impl CoreWrite for EvpHash {
    fn write(&mut self, buf: &[u8]) -> CryptoResult<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> CryptoResult<()> {
        self.0.flush()
    }
}

impl HashUser for EvpHash {
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
