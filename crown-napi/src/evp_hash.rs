use crate::crypto_err;
use crown::core::{CoreRead, CoreWrite};
use crown::envelope::EvpHash;
use crown::hash::HashUser;
use napi::bindgen_prelude::*;

#[napi]
pub struct Hash(EvpHash);

macro_rules! impl_hash_methods {
    (
        normal: [$($normal:ident),* $(,)?],
        variant: [$($variant:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                #[napi]
                impl Hash {
                    #[napi]
                    pub fn [<new_ $normal:lower>]() -> Result<Hash> {
                        match EvpHash::[<new_ $normal:lower>]() {
                            Ok(hash) => Ok(Hash(hash)),
                            Err(e) => Err(crypto_err("Failed to create hash", e)),
                        }
                    }

                    #[napi]
                    pub fn [<new_ $normal:lower _hmac>](key: &[u8]) -> Result<Hash> {
                        match EvpHash::[<new_ $normal:lower _hmac>](key) {
                            Ok(hash) => Ok(Hash(hash)),
                            Err(e) => Err(crypto_err("Failed to create HMAC", e)),
                        }
                    }
                }
            }
        )*
        $(
            paste::paste! {
                #[napi]
                impl Hash {
                    #[napi]
                    pub fn [<new_ $variant:lower>](key: Option<Buffer>, output_len: u32) -> Result<Hash> {
                        let key_opt = key.map(|k| k.as_ref().to_vec());
                        let key_opt = key_opt.as_ref().map(|k| k.as_slice());
                        match EvpHash::[<new_ $variant:lower>](key_opt, output_len as usize) {
                            Ok(hash) => Ok(Hash(hash)),
                            Err(e) => Err(crypto_err("Failed to create hash", e)),
                        }
                    }
                }
            }
        )*
    };
}

impl_hash_methods!(
    normal: [
        md2, md4, md5, sha1, sha224, sha256, sha384, sha512,
        sha512_224, sha512_256, sha3_224, sha3_256, sha3_384,
        sha3_512, shake128, shake256, sm3,
        md5_sha1, ripemd160, mdc2, whirlpool
    ],
    variant: [blake2s, blake2b],
);

#[napi]
impl Hash {
    #[napi]
    pub fn write(&mut self, data: &[u8]) -> Result<u32> {
        match self.0.write(data) {
            Ok(written) => Ok(written as u32),
            Err(e) => Err(crypto_err("Write failed", e)),
        }
    }

    #[napi]
    pub fn flush(&mut self) -> Result<()> {
        match self.0.flush() {
            Ok(_) => Ok(()),
            Err(e) => Err(crypto_err("Flush failed", e)),
        }
    }

    #[napi]
    pub fn read(&mut self, mut buf: Buffer) -> Result<u32> {
        match self.0.read(&mut buf) {
            Ok(read) => Ok(read as u32),
            Err(e) => Err(crypto_err("Read failed", e)),
        }
    }

    #[napi]
    pub fn sum(&mut self) -> Buffer {
        Buffer::from(self.0.sum())
    }

    #[napi]
    pub fn reset(&mut self) {
        self.0.reset();
    }

    #[napi]
    pub fn size(&self) -> u32 {
        self.0.size() as u32
    }

    #[napi]
    pub fn block_size(&self) -> u32 {
        self.0.block_size() as u32
    }
}
