use crate::core::{CoreRead, CoreWrite};
use crate::error::CryptoResult;
use crate::hash::Hash;
use crate::hash::HashUser;
use crate::mac::hmac::HMAC;
use alloc::boxed::Box;
use alloc::vec;
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
            md2, crate::hash::md2::new_md2,
            md4, crate::hash::md4::new_md4,
            md5, crate::hash::md5::new_md5,
            sha1, crate::hash::sha1::new,
            sha224, crate::hash::sha256::new224,
            sha256, crate::hash::sha256::new256,
            sha2_256_192, crate::hash::sha256::new256_192,
            sha384, crate::hash::sha512::new384,
            sha512, crate::hash::sha512::new512,
            sha512_224, crate::hash::sha512::new512_224,
            sha512_256, crate::hash::sha512::new512_256,
            sha3_224, crate::hash::sha3::new224,
            sha3_256, crate::hash::sha3::new256,
            sha3_384, crate::hash::sha3::new384,
            sha3_512, crate::hash::sha3::new512,
            shake128, crate::hash::sha3::new_shake128,
            shake256, crate::hash::sha3::new_shake256,
            keccak224, crate::hash::sha3::new_legacy_keccak224,
            keccak256, crate::hash::sha3::new_legacy_keccak256,
            keccak384, crate::hash::sha3::new_legacy_keccak384,
            keccak512, crate::hash::sha3::new_legacy_keccak512,
            keccak_kmac_128, crate::hash::sha3::new_keccak_kmac128,
            keccak_kmac_256, crate::hash::sha3::new_keccak_kmac256,
            sm3, crate::hash::sm3::new_sm3,
            md5_sha1, crate::hash::md5_sha1::new_md5_sha1,
            ripemd160, crate::hash::ripemd160::new_ripemd160,
            mdc2, crate::hash::mdc2::new_mdc2,
            whirlpool, crate::hash::whirlpool::new_whirlpool,
        ],
        variant: [
            blake2s, crate::hash::blake2s::Blake2sVariable::new,
            blake2b, crate::hash::blake2b::Blake2bVariable::new,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test for the OpenSSL-parity digest factories added on
    /// 2026-10-03: `abc` digest bytes come from the vendored OpenSSL 3.5.8 CLI.
    #[test]
    fn test_openssl_parity_digest_factories() {
        type Factory = fn() -> CryptoResult<EvpHash>;

        let cases: [(&str, Factory, &str); 7] = [
            (
                "keccak224",
                EvpHash::new_keccak224,
                "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8",
            ),
            (
                "keccak256",
                EvpHash::new_keccak256,
                "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
            ),
            (
                "keccak384",
                EvpHash::new_keccak384,
                "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99\
                 f8c681e4afaf31a34db29fb763e3c28e",
            ),
            (
                "keccak512",
                EvpHash::new_keccak512,
                "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5\
                 d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96",
            ),
            (
                "sha2_256_192",
                EvpHash::new_sha2_256_192,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9c",
            ),
            (
                "keccak_kmac_128",
                EvpHash::new_keccak_kmac_128,
                "3bcfe6e0471a2168f61c444843e32aea0a09ec15bd9155f169189147f98c11fc",
            ),
            (
                "keccak_kmac_256",
                EvpHash::new_keccak_kmac_256,
                "f4e4a2d747910716f38c8ec58a5a50f6b0ea4ebd1e4c92a19e9b36ae640580f1\
                 fda41b8b534dfc57a1a719528dadc28e3e6181daba9dc9595e459e249b2bcd95",
            ),
        ];

        for (name, new, expected) in cases {
            let mut h = new().unwrap();
            h.write_all(b"abc").unwrap();
            assert_eq!(hex::encode(h.sum()), expected, "{name}");
        }
    }
}
